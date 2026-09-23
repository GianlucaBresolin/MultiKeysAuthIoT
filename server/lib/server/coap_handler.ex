defmodule Server.CoapHandler do
  @behaviour :coap_resource

  require Record
  Record.defrecord(:coap_content, Record.extract(:coap_content, from_lib: "gen_coap/include/coap.hrl"))

  def coap_discover(_prefix, _args), do: []

  def coap_get(_ctx, _prefix, _suffix, _request), do: {:error, :not_found}
  def coap_get(_ctx, _prefix, _suffix, _query, _request), do: {:error, :not_found}

  def coap_post(_ctx, prefix, _suffix, request) do
    payload = coap_content(request, :payload)

    result =
      case prefix do
        ["auth", "m1"] -> Server.process_m1(payload)
        ["auth", "m3"] -> Server.process_m3(payload)
        ["data"] -> Server.process_data(payload)
        _ -> {:error, :not_found}
      end

    case result do
      {:ok, {:content, resp_payload}} ->
        {:ok, :content, coap_content(payload: resp_payload)}

      {:error, {:session_timeout, resp_payload}} ->
        {:ok, :content, coap_content(payload: resp_payload)}

      {:error, _reason} ->
        {:error, :bad_request}
    end
  end

  def coap_put(_ctx, _prefix, _suffix, _request), do: {:error, :method_not_allowed}
  def coap_delete(_ctx, _prefix, _request), do: {:error, :method_not_allowed}
  def coap_delete(_ctx, _prefix, _suffix, _request), do: {:error, :method_not_allowed}
  def coap_observe(_ctx, _prefix, _suffix, _request), do: {:error, :method_not_allowed}
  def coap_unobserve(_state), do: :ok
  def handle_info(_info, state), do: {:noreply, state}
  def coap_ack(_ref, state), do: {:ok, state}
end
