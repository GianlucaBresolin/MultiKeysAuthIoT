defmodule Server do
  use GenServer
  require Logger

  alias Server.SecureVault

  ########################################################################
  ### Server API
  ########################################################################

  def start_link(iot_uids, keys, p) do
    GenServer.start_link(__MODULE__, {iot_uids, keys, p}, name: __MODULE__)
  end

  def process_m1(payload) do
    <<uid_len::8, iot_uid::binary-size(uid_len)>> = payload

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

  def process_m3(payload) do
    <<uid_len::8, iot_uid::binary-size(uid_len), m3::binary>> = payload

    case GenServer.call(__MODULE__, {:process_m3, iot_uid, m3}) do
      {:ok, m4} ->
        {:ok, {:content, m4}}

      {:error, reason} ->
        {:error, {:bad_request, reason}}
    end
  end

  def process_data(payload) do
    <<uid_len::8, iot_uid::binary-size(uid_len), encrypted_data::binary>> = payload

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

    state = %{
      iot_uids: iot_uids,
      auth_sessions: %{},
      session_keys: %{},
      n: n,
      p: p
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:process_m1, m1}, _from, state) do
    # check if m1 is a valid iot_device_uid
    if Enum.member?(state.iot_uids, m1) do
      c1 = Enum.take_random(0..(state.n-1), state.p)
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
        {:reply, {:error, :auth_session_not_found}}

      {:ok, %{k1: k1, r1: r1}} ->
        decrypted_m3 = decrypt(k1, m3)
        p = state.p
        <<r1_recv::binary-8, t1::binary-16, indices::binary-size(^p), r2::binary-8>> = decrypted_m3

        updated_auth_sessions = Map.delete(state.auth_sessions, iot_uid)

        if r1_recv == r1 do
          Logger.info("Device #{iot_uid} Auth: Succesfull. \n")

          c2 = :binary.bin_to_list(indices)

          k2 = generate_key(iot_uid, c2)

          t2 = :crypto.strong_rand_bytes(16)

          encrypt_key = xor_binaries(k2, t1)
          r2_t2 = concat_binaries(r2, t2)

          m4 = encrypt(encrypt_key, r2_t2)

          session_key = xor_binaries(k1, k2)
          updated_session_keys = Map.put(state.session_keys, iot_uid, session_key)

          {:reply, {:ok, m4}, %{state | session_keys: updated_session_keys, auth_sessions: updated_auth_sessions}}
        else
          Logger.error("Device #{iot_uid} Auth: failed challenge in M3.")
          {:reply, {:error, :invalid_response}, %{state | auth_sessions: updated_auth_sessions}}
        end
    end
  end

  @impl true
  def handle_call({:process_data, iot_uid, encrypted_data}, _from, state) do
    case Map.fetch(state.session_keys, iot_uid) do
      :error ->
        {:reply, {:error, :auth_session_not_found}, state}

      {:ok, session_key} ->
        data = decrypt(session_key, encrypted_data)

        IO.puts "[server] Received data: #{inspect(data)}"
        {:reply, :ok, state}
    end
  end

  ########################################################################
  ### Internal Utils
  ########################################################################
  defp generate_key(iot_uid, indeces) do
    keys = SecureVault.get_keys(iot_uid)

    indeces
    |> Enum.map(fn index -> Enum.at(keys, index) end)
    |> Enum.reduce(fn key, acc -> xor_binaries(acc, key) end)
  end

  defp xor_binaries(a, b), do: :crypto.exor(a, b)

  defp concat_binaries(a, b), do: a <> b

  def encrypt(key, plaintext) do
    iv = :crypto.strong_rand_bytes(16)
    padded = pkcs7_pad(plaintext, 16)
    encrypted = :crypto.crypto_one_time(:aes_128_cbc, key, iv, padded, true)
    concat_binaries(iv, encrypted)
  end

  defp pkcs7_pad(data, block_size) do
    pad_len = rem(block_size - rem(byte_size(data), block_size), block_size)
    pad_len = if pad_len == 0, do: block_size, else: pad_len
    data <> :binary.copy(<<pad_len>>, pad_len)
  end

  defp pkcs7_unpad(data) do
    pad_len = :binary.last(data)
    end_index = byte_size(data) - pad_len

    if pad_len > 0 and pad_len <= byte_size(data) and
         binary_part(data, end_index, pad_len) == :binary.copy(<<pad_len>>, pad_len) do
      binary_part(data, 0, end_index)
    else
      data
    end
  end

  defp decrypt(key, data) do
    <<iv::binary-16, encrypted::binary>> = data
    padded = :crypto.crypto_one_time(:aes_128_cbc, key, iv, encrypted, false)
    pkcs7_unpad(padded)
  end
end
