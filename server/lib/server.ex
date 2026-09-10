defmodule Server do
  use GenServer
  require Logger

  alias Server.SecureVault
  alias Server.Crypto

  @auth_session_timeout String.to_integer(System.get_env("AUTH_SESSION_TIMEOUT", "3600"))

  ########################################################################
  ### Server API
  ########################################################################

  def start_link(iot_uids, keys, p) do
    GenServer.start_link(__MODULE__, {iot_uids, keys, p}, name: __MODULE__)
  end

  def process_m1(payload, _request \\ %{}) do
    IO.puts("Server: Received M1 payload: #{inspect(payload)}")
    # Support two formats: [uid_len(1) | uid_bytes] or single-byte numeric uid
    {iot_uid, _rest} =
      case payload do
        <<uid_len::8, iot_uid::binary-size(uid_len), rest::binary>> -> {iot_uid, rest}
        <<uid_u8::8, rest::binary>> -> {<<uid_u8::8>>, rest}
        _ -> {payload, <<>>}
      end

    case GenServer.call(__MODULE__, {:process_m1, iot_uid}) do
      {:ok, {c1, r1}} ->
        p = length(c1)
        indices_bin = :erlang.iolist_to_binary(c1)
        bin_m2 = <<p::8, indices_bin::binary, r1::binary>>
        {:ok, {:content, bin_m2}}

      {:error, reason} ->
        {:error, {:bad_request, reason}}
    end
  end

  def process_m3(payload, _request \\ %{}) do
    {iot_uid, m3} =
      case payload do
        <<uid_len::8, iot_uid::binary-size(uid_len), rest::binary>> -> {iot_uid, rest}
        <<uid_u8::8, rest::binary>> -> {<<uid_u8::8>>, rest}
        _ -> {<<>>, payload}
      end

    case GenServer.call(__MODULE__, {:process_m3, iot_uid, m3}) do
      {:ok, m4} ->
        {:ok, {:content, m4}}

      {:error, reason} ->
        {:error, {:bad_request, reason}}
    end
  end

  def process_data(payload, _request \\ %{}) do
    {iot_uid, encrypted_data} =
      case payload do
        <<uid_len::8, iot_uid::binary-size(uid_len), rest::binary>> -> {iot_uid, rest}
        <<uid_u8::8, rest::binary>> -> {<<uid_u8::8>>, rest}
        _ -> {<<>>, payload}
      end

    case GenServer.call(__MODULE__, {:process_data, iot_uid, encrypted_data}) do
      :ok ->
        {:ok, :changed}

      {:error, reason} ->
        {:error, {:bad_request, reason}}
    end
  end

  ########################################################################
  ### GenServer Implementation
  ########################################################################

  @impl true
  def init({iot_uids, keys, p}) do
    n = length(keys)

    # stores the keys in a secure way
    Enum.each(iot_uids, fn uid ->
      SecureVault.store_keys(uid, keys)
    end)

    IO.puts("Server: SecureVault initialized with #{n} keys for #{length(iot_uids)} IoT devices.")

    state = %{
      iot_uids: iot_uids,
      auth_sessions: %{},
      sessions: %{},
      n: n,
      p: p
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:process_m1, m1}, _from, state) do
    # check if m1 is a valid iot_device_uid (both are binaries)
    if Enum.member?(state.iot_uids, m1) do
      c1 = Enum.take_random(0..(state.n - 1), state.p)
      r1 = :crypto.strong_rand_bytes(8)

      m2 = {c1, r1}

      k1 = generate_key(m1, c1)

      updated_auth_sessions = Map.put(state.auth_sessions, m1, %{k1: k1, r1: r1})
      {:reply, {:ok, m2}, %{state | auth_sessions: updated_auth_sessions}}
    else
      {:reply, {:error, :unkown_iot_dev}, state}
    end
  end

  @impl true
  def handle_call({:process_m3, iot_uid, m3}, _from, state) do
    # decrypt m3
    case Map.fetch(state.auth_sessions, iot_uid) do
      :error ->
        {:reply, {:error, :auth_session_not_found}, state}

      {:ok, %{k1: k1, r1: r1}} ->
        decrypted_m3 = Crypto.decrypt_aes_cbc(k1, m3)
        p = state.p
        # decrypted format expected: r1(8) || t1(8) || indices(p bytes) || r2(8)
        <<r1_recv::binary-8, t1::binary-8, indices::binary-size(^p), r2::binary-8>> = decrypted_m3

        updated_auth_sessions = Map.delete(state.auth_sessions, iot_uid)

        if r1_recv == r1 do
          Logger.info("Device #{inspect(iot_uid)} Auth: Successful.")

          c2 = :binary.bin_to_list(indices)

          k2 = generate_key(iot_uid, c2)

          t2 = :crypto.strong_rand_bytes(8)

          encrypt_key = xor_binaries(k2, expand_key(t1, byte_size(k2)))

          r2_t2 = concat_binaries(r2, t2)

          m4 = Server.Crypto.encrypt_aes_cbc(encrypt_key, r2_t2)

          session_key = expand_xor(t1, t2, 32)
          session_expiry =
            DateTime.utc_now()
            |> DateTime.add(@auth_session_timeout, :second)

          iot_session = %{
            key: session_key,
            data: <<>>,
            session_expiry: session_expiry
          }
          updated_sessions = Map.put(state.sessions, iot_uid, iot_session)

          {:reply, {:ok, m4}, %{state | sessions: updated_sessions, auth_sessions: updated_auth_sessions}}
        else
          Logger.error("Device #{inspect(iot_uid)} Auth: failed challenge in M3.")
          {:reply, {:error, :invalid_response}, %{state | auth_sessions: updated_auth_sessions}}
        end
    end
  end

  @impl true
  def handle_call({:process_data, iot_uid, encrypted_data}, _from, state) do
    case Map.fetch(state.sessions, iot_uid) do
      :error ->
        {:reply, {:error, :auth_session_not_found}, state}

      {:ok, session_state} ->
        session_key = Map.get(session_state, :key)

        cond do
          session_key == nil ->
            {:reply, {:error, :unauthorized}, state}

          session_timeout?(session_state) ->
            change_keys(iot_uid, Map.get(session_state, :data))
            updated_sessions = Map.delete(state.sessions, iot_uid)
            {:reply, {:error, :session_timeout}, %{state | sessions: updated_sessions}}

          true ->
            data = Server.Crypto.decrypt_aes_cbc(session_key, encrypted_data)

            Logger.info("[server] Received data: #{inspect(data)}")

            existing = Map.get(session_state, :data, <<>>)
            updated_session_state = Map.put(session_state, :data, existing <> data)
            updated_sessions = Map.put(state.sessions, iot_uid, updated_session_state)

            {:reply, :ok, %{state | sessions: updated_sessions}}
        end
    end
  end

  ########################################################################
  ### Internal Utils
  ########################################################################
  defp generate_key(iot_uid, indeces) do
    keys = SecureVault.get_keys(iot_uid)
             |> Enum.map(fn k ->
               case Base.decode64(k) do
                 {:ok, bin} -> bin
                 _ -> k
               end
             end)

    indeces
    |> Enum.map(fn index -> Enum.at(keys, index) end)
    |> Enum.reduce(fn key, acc -> xor_binaries(acc, key) end)
  end

  defp xor_binaries(a, b), do: :crypto.exor(a, b)

  defp concat_binaries(a, b), do: a <> b

  defp session_timeout?(session_state) do
    case Map.get(session_state, :session_expiry) do
      nil -> true
      expiry -> DateTime.compare(DateTime.utc_now(), expiry) == :gt
    end
  end

  defp change_keys(iot_uid, exchanged_data) do
    keys = SecureVault.get_keys(iot_uid)
    concat_keys = Enum.map(keys, fn k ->
      case Base.decode64(k) do
        {:ok, bin} -> bin
        _ -> k
      end
    end) |> :erlang.iolist_to_binary()

    h = Crypto.hmac(concat_keys, exchanged_data)
    k = bit_size(h)

    vault_partitions = split_with_padding(concat_keys, k)

    new_keys = generate_new_keys(vault_partitions, h)

    SecureVault.store_keys(iot_uid, new_keys)
  end

  defp expand_key(short, len) do
    # repeat the bytes of short until len reached
    repeated = :binary.copy(short, div(len, byte_size(short)) + 1)
    binary_part(repeated, 0, len)
  end

  defp expand_xor(a, b, out_len) do
    a_rep = expand_key(a, out_len)
    b_rep = expand_key(b, out_len)
    xor_binaries(a_rep, b_rep)
  end

  defp split_with_padding(data, k) do
    padding = rem(k - rem(bit_size(data), k), k)

    data_to_split = <<data::bitstring, 0::size(padding)>>

    split_bits(data_to_split, k)
  end

  def split_bits(k, data, acc \\ [])
  def split_bits(k, data, acc) do
    case data do
      <<chunk::size(^k)-bits, rest::bitstring>> ->
        split_bits(k, rest, [chunk | acc])

      _ ->
        Enum.reverse(acc)
    end
  end

  def generate_new_keys(vault_partitions, h, i \\ 0, acc \\ [])
  def generate_new_keys([], _h, _i, acc), do: Enum.reverse(acc)
  def generate_new_keys([vault_partition | rest], h, i, acc) do
    i_bin = <<i::size(bit_size(h))>>
    new_key = xor_binaries(vault_partition, xor_binaries(h, i_bin))

    generate_new_keys(rest, h, i + 1, [new_key | acc])
  end
end
