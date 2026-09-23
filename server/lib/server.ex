defmodule Server do
  use GenServer
  require Logger

  alias Server.SecureVault
  alias Server.Crypto

  @auth_session_timeout String.to_integer(System.get_env("AUTH_SESSION_TIMEOUT", "20"))

  ########################################################################
  ### Server API
  ########################################################################

  def start_link(iot_uids, keys, p) do
    GenServer.start_link(__MODULE__, {iot_uids, keys, p}, name: __MODULE__)
  end

  def process_m1(payload, _request \\ %{}) do
    {m1, _rest} =
      case payload do
        <<m1::binary-size(9), rest::binary>> -> {m1, rest}
        _ -> {payload, <<>>}
      end

    case GenServer.call(__MODULE__, {:process_m1, m1}) do
      {:ok, {c1, r1}} ->
        indices_bin = :erlang.iolist_to_binary(c1)
        bin_m2 = <<indices_bin::binary, r1::binary>>
        {:ok, {:content, bin_m2}}

      {:error, reason} ->
        {:error, {:bad_request, reason}}
    end
  end

  def process_m3(payload, _request \\ %{}) do
    {session_id, m3} =
      case payload do
        <<session_id::64, m3::binary>> -> {session_id, m3}
        _ -> {<<>>, payload}
      end

    case GenServer.call(__MODULE__, {:process_m3, session_id, m3}) do
      {:ok, m4} ->
        {:ok, {:content, m4}}

      {:error, reason} ->
        {:error, {:bad_request, reason}}
    end
  end

  def process_data(payload, _request \\ %{}) do
    {session_id, encrypted_data} =
      case payload do
        <<session_id::64, data::binary>> -> {session_id, data}
        _ -> {<<>>, payload}
      end

    case GenServer.call(__MODULE__, {:process_data, session_id, encrypted_data}) do
      :ok ->
        {:ok, {:content, "ACK"}}

      {:error, :session_timeout} ->
        {:error, {:session_timeout, "ERROR:auth_session_timeout"}}

      {:error, reason} ->
        Logger.error("Failed to process data, reason: #{inspect(reason)}")
        {:error, reason}
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
      case SecureVault.store_keys(uid, keys) do
        {:ok, {{_, status, _}, _, _body}} when status in 200..299 ->
          :ok

        other ->
          IO.puts("WARNING: store_keys failed for uid #{inspect(uid)}: #{inspect(other)}")
      end
    end)

    IO.puts("Server initalized with SecureVault for #{length(iot_uids)} IoT devices.")

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
    case m1 do
      <<iot_uid::size(8), session_id::size(64)>> ->
        if Enum.member?(state.iot_uids, <<iot_uid::8>>) do
          c1 = Enum.take_random(0..(state.n - 1), state.p)
          r1 = :crypto.strong_rand_bytes(8)

          m2 = {c1, r1}

          k1 = generate_key(<<iot_uid>>, c1)

          updated_auth_sessions = Map.put(state.auth_sessions, session_id, %{iot_uid: iot_uid, k1: k1, r1: r1})

          IO.puts("""
          Rx M1:
          - IOT_UID: #{iot_uid}
          - SESSION_ID: #{session_id}

          Tx M2:
          - C1: #{inspect(c1)}
          - R1: #{Base.encode16(r1, case: :lower)}
          """)

          {:reply, {:ok, m2}, %{state | auth_sessions: updated_auth_sessions}}
        else
          {:reply, {:error, :unkown_iot_dev}, state}
        end

      _ ->
        Logger.error("Failed Auth: invalid M1 values/format.")
        {:reply, {:error, :invalid_m1}, state}
    end
  end

  @impl true
  def handle_call({:process_m3, session_id, m3}, _from, state) do
    case Map.fetch(state.auth_sessions, session_id) do
      :error ->
        {:reply, {:error, :auth_session_not_found}, state}

      {:ok, %{iot_uid: iot_uid, k1: k1, r1: r1}} ->
        decrypted_m3 = Crypto.decrypt_aes_cbc(k1, m3)
        p = state.p
        # decrypted format expected: r1(8) || t1(8) || indices(p bytes) || r2(8)
        <<r1_recv::binary-8, t1::binary-8, indices::binary-size(^p), r2::binary-8>> = decrypted_m3

        updated_auth_sessions = Map.delete(state.auth_sessions, session_id)

        if r1_recv == r1 do
          c2 = :binary.bin_to_list(indices)
          k2 = generate_key(<<iot_uid>>, c2)
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
            iot_uid: iot_uid,
            data: <<>>,
            session_expiry: session_expiry
          }
          updated_sessions = Map.put(state.sessions, session_id, iot_session)

          IO.puts("""
          Rx M3:
          - SESSION_ID: #{session_id}
          - ENCRYPTED_M3: #{Base.encode16(m3, case: :lower)}
          - R1: #{Base.encode16(r1, case: :lower)}
          - T1: #{Base.encode16(t1, case: :lower)}
          - C2: #{inspect(c2)}

          Tx M4:
          - K2: #{Base.encode16(k2, case: :lower)}
          - T1: #{Base.encode16(t1, case: :lower)}
          - R2: #{Base.encode16(r2, case: :lower)}
          - T2: #{Base.encode16(t2, case: :lower)}
          - ENCRYPTED_M4: #{Base.encode16(m4, case: :lower)}

          SESSION_KEY: #{Base.encode16(session_key, case: :lower)}
          """)

          {:reply, {:ok, m4}, %{state | sessions: updated_sessions, auth_sessions: updated_auth_sessions}}
        else
          Logger.error("Device #{inspect(iot_uid)} Auth: failed challenge in M3.")
          {:reply, {:error, :invalid_response}, %{state | auth_sessions: updated_auth_sessions}}
        end
    end
  end

  @impl true
  def handle_call({:process_data, session_id, encrypted_data}, _from, state) do
    case Map.fetch(state.sessions, session_id) do
      :error ->
        {:reply, {:error, :auth_session_not_found}, state}

      {:ok, session_state} ->
        session_key = Map.get(session_state, :key)

        cond do
          session_key == nil ->
            {:reply, {:error, :unauthorized}, state}

          session_timeout?(session_state) ->
            change_keys(Map.get(session_state, :iot_uid), Map.get(session_state, :data))
            updated_sessions = Map.delete(state.sessions, session_id)
            {:reply, {:error, :session_timeout}, %{state | sessions: updated_sessions}}

          true ->
            data = Server.Crypto.decrypt_aes_cbc(session_key, encrypted_data)

            existing = Map.get(session_state, :data, <<>>)
            updated_session_state = Map.put(session_state, :data, existing <> data)
            updated_sessions = Map.put(state.sessions, session_id, updated_session_state)

            IO.puts """
            Encrypted Data: #{inspect(encrypted_data)}
            Telemetry Data: #{inspect(data)}
            """

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
    keys = SecureVault.get_keys(<<iot_uid>>)
    concat_keys = Enum.map(keys, fn k ->
      case Base.decode64(k) do
        {:ok, bin} -> bin
        _ -> k
      end
    end) |> :erlang.iolist_to_binary()

    h = Crypto.hmac(concat_keys, exchanged_data)
    k = bit_size(h)

    vault_partitions = split_with_padding(concat_keys, k)

    new_keys_raw = generate_new_keys(vault_partitions, h)
    new_keys_b64 = Enum.map(new_keys_raw, &Base.encode64/1)

    case SecureVault.store_keys(<<iot_uid>>, new_keys_b64) do
      {:ok, {{_, status, _}, _, _body}} when status in 200..299 ->
        IO.puts("Change keys status: success.")

      other ->
        IO.puts("change_keys: FAILED to store new keys: #{inspect(other)}")
    end
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

  def split_bits(data, k, acc \\ [])
  def split_bits(data, k, acc) do
    case data do
      <<chunk::size(^k)-bits, rest::bitstring>> ->
        split_bits(rest, k, [chunk | acc])

      _ ->
        Enum.reverse(acc)
    end
  end

  def generate_new_keys(vault_partitions, h, i \\ 0, acc \\ [])
  def generate_new_keys([], _h, _i, acc), do: Enum.reverse(acc)
  def generate_new_keys([vault_partition | rest], h, i, acc) do
    mask = for <<byte <- h>>, into: <<>>, do: <<:erlang.bxor(byte, i)::8>>
    new_key = xor_binaries(vault_partition, mask)
    generate_new_keys(rest, h, i + 1, [new_key | acc])
  end
end
