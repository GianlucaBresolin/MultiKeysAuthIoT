defmodule Server.SecureVault do
  ########################################################################
  ### SecureVault Interface
  ########################################################################
  def store_keys(device_uid, keys) do
    uid_s = uid_to_string(device_uid)
    url = "#{vault_addr()}/v1/secret/data/iot_device/#{uid_s}"
    body = Jason.encode!(%{data: %{keys: keys}})

    :httpc.request(:put, {String.to_charlist(url),
      [{~c"X-Vault-Token", String.to_charlist(vault_token())}],
      ~c"application/json", body}, http_opts(), [])
  end

  def get_keys(device_uid) do
    uid_s = uid_to_string(device_uid)
    url = "#{vault_addr()}/v1/secret/data/iot_device/#{uid_s}"

    case :httpc.request(:get, {String.to_charlist(url),
      [{~c"X-Vault-Token", String.to_charlist(vault_token())}]}, http_opts(), []) do
      {:ok, {_, _, body}} ->
        %{"data" => %{"data" => %{"keys" => keys}}} = Jason.decode!(to_string(body))
        keys
      err -> err
    end
  end

  ########################################################################
  ### Internal Utils
  ########################################################################
  defp vault_addr, do: System.get_env("VAULT_ADDR", "https://vault:8200")
  defp ca_cert, do: System.get_env("VAULT_CACERT", "/tls/vault-cert.pem")
  defp vault_token do
    "/vault-init-out/service-token.txt"
    |> File.read!()
    |> String.trim()
  end

  defp http_opts do
    cacert = ca_cert() |> File.read!() |> :public_key.pem_decode() |> hd() |> elem(1)

    verify_fun = {
      fn
        _, {:bad_cert, :selfsigned_peer}, user_state -> {:valid, user_state}
        _, {:bad_cert, :unknown_ca}, user_state -> {:valid, user_state}
        _, {:bad_cert, reason}, _ -> {:fail, reason}
        _, {:extension, _}, user_state -> {:unknown, user_state}
        _, :valid, user_state -> {:valid, user_state}
        _, :valid_peer, user_state -> {:valid, user_state}
      end,
      []
    }

    [ssl: [
      verify: :verify_peer,
      server_name_indication: ~c"vault",
      versions: [:"tlsv1.2", :"tlsv1.3"],
      cacerts: [cacert],
      verify_fun: verify_fun
    ]]
  end

  defp uid_to_string(uid) when is_binary(uid) do
    case byte_size(uid) do
      1 -> Integer.to_string(:binary.at(uid, 0))
      _ -> to_string(uid)
    end
  end
end
