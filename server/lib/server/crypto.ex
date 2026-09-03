defmodule Server.Crypto do
  def hmac(data, key, algorithm \\ :sha256) do
    :crypto.mac(:hmac, algorithm, key, data)
  end

  def encrypt_aes_cbc(key, plaintext) do
    iv = :crypto.strong_rand_bytes(16)
    padded = pkcs7_pad(plaintext, 16)
    encrypted = :crypto.crypto_one_time(:aes_128_cbc, key, iv, padded, true)
    concat_binaries(iv, encrypted)
  end

  def decrypt_aes_cbc(key, data) do
    <<iv::binary-16, encrypted::binary>> = data
    padded = :crypto.crypto_one_time(:aes_128_cbc, key, iv, encrypted, false)
    pkcs7_unpad(padded)
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
end
