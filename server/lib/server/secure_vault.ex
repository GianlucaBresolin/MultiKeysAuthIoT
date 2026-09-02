defmodule Server.SecureVault do
  defp vault_addr, do: System.get_env("VAULT_ADDR", "https://vault:8200")
  defp ca_cert, do: System.get_env("VAULT_CACERT", "/tls/vault-cert.pem")

  defp vault_token do
    "/vault-init-out/service-token.txt"
    |> File.read!()
    |> String.trim()
  end

  defp http_opts do
    [ssl: [cacertfile: String.to_charlist(ca_cert()), verify: :verify_peer]]
  end

  def store_keys(device_uid, keys) do
    url = "#{vault_addr()}/v1/secret/data/iot_device/#{device_uid}"
    body = Jason.encode!(%{data: %{keys: keys}})

    :httpc.request(:put, {String.to_charlist(url),
      [{~c"X-Vault-Token", String.to_charlist(vault_token())}],
      ~c"application/json", body}, http_opts(), [])
  end

  def get_keys(device_uid) do
    url = "#{vault_addr()}/v1/secret/data/iot_device/#{device_uid}"

    case :httpc.request(:get, {String.to_charlist(url),
      [{~c"X-Vault-Token", String.to_charlist(vault_token())}]}, http_opts(), []) do
      {:ok, {_, _, body}} ->
        %{"data" => %{"data" => %{"keys" => keys}}} = Jason.decode!(to_string(body))
        keys
      err -> err
    end
  end
end
