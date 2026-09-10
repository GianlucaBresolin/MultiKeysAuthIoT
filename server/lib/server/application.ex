defmodule Server.Application do
  use Application

  @impl true
  def start(_type, _args) do
    raw_iot_uids = String.split(System.get_env("IOT_UIDS", ""), ",")
    iot_uids = Enum.map(raw_iot_uids, fn s ->
      case Integer.parse(s) do
        {n, _} when n >= 0 and n <= 255 -> <<n::8>>
        _ -> to_string(s) |> to_charlist() |> :erlang.list_to_binary()
      end
    end)

    keys = System.get_env("SERVER_KEYS", "{}") |> Jason.decode!()
    p = String.to_integer(System.fetch_env!("SERVER_P"))

    children = [
      %{
        id: Server,
        start: {Server, :start_link, [iot_uids, keys, p]}
      }
    ]

    opts = [strategy: :one_for_one, name: Server.Application]
    {:ok, pid} = Supervisor.start_link(children, opts)

    {:ok, _} = :application.ensure_all_started(:gen_coap)

    :ok = :coap_server_registry.add_handler(["auth", "m1"], Server.CoapHandler, [])
    :ok = :coap_server_registry.add_handler(["auth", "m3"], Server.CoapHandler, [])
    :ok = :coap_server_registry.add_handler(["data"], Server.CoapHandler, [])
    {:ok, _} = :coap_server.start_udp(:coap_udp_socket)

    IO.puts("Server started with IOT_UIDS: #{inspect(iot_uids)}, SERVER_KEYS: #{inspect(keys)}, SERVER_P: #{p}")
    {:ok, pid}
  end
end
