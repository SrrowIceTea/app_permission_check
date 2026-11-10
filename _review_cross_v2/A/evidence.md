# 复核证据

以下记录来自授权测试。正文中仅保留本轮判断所需字段。

## Home Assistant · 电量读取与请求

- **P01** lab_power 事件 14 与 ha_transport 事件 2 是否构成同一轮电量读取与请求？
- **P02** lab_power 事件 14 与 ha_transport 事件 3 是否构成同一轮电量读取与请求？
- **P03** lab_power 事件 8 与 ha_transport 事件 3 是否构成同一轮电量读取与请求？
- **P04** lab_power 事件 8 与 ha_transport 事件 2 是否构成同一轮电量读取与请求？
- **P05** lab_power 事件 2 与 ha_transport 事件 2 是否构成同一轮电量读取与请求？
- **P06** lab_power 事件 2 与 ha_transport 事件 3 是否构成同一轮电量读取与请求？

```json
{
  "read_events": [
    {
      "src": "lab_power",
      "evt_id": 2,
      "uid": 1010251,
      "pid": 3254,
      "ts": 1793691790747,
      "host_received_ts": 1793691791798,
      "field": "level",
      "value": 73,
      "fallback": -1
    },
    {
      "src": "lab_power",
      "evt_id": 3,
      "uid": 1010251,
      "pid": 3254,
      "ts": 1793691790750,
      "host_received_ts": 1793691791801,
      "field": "scale",
      "value": 100,
      "fallback": -1
    },
    {
      "src": "lab_power",
      "evt_id": 8,
      "uid": 1010251,
      "pid": 3254,
      "ts": 1793691791925,
      "host_received_ts": 1793691792976,
      "field": "level",
      "value": 61,
      "fallback": -1
    },
    {
      "src": "lab_power",
      "evt_id": 9,
      "uid": 1010251,
      "pid": 3254,
      "ts": 1793691791931,
      "host_received_ts": 1793691792979,
      "field": "scale",
      "value": 100,
      "fallback": -1
    },
    {
      "src": "lab_power",
      "evt_id": 14,
      "uid": 1010251,
      "pid": 3254,
      "ts": 1793691793048,
      "host_received_ts": 1793691794097,
      "field": "level",
      "value": 100,
      "fallback": -1
    },
    {
      "src": "lab_power",
      "evt_id": 15,
      "uid": 1010251,
      "pid": 3254,
      "ts": 1793691793053,
      "host_received_ts": 1793691794101,
      "field": "scale",
      "value": 100,
      "fallback": -1
    }
  ],
  "request_events": [
    {
      "src": "ha_transport",
      "evt_id": 2,
      "uid": 1010251,
      "pid": 3254,
      "ts": 1793691791458,
      "host_received_ts": 1793691792508,
      "method": "POST",
      "request_started_ts": 1793691791448,
      "sensor_id": "battery_level",
      "state": 73,
      "status": 200,
      "body_complete": true
    },
    {
      "src": "ha_transport",
      "evt_id": 3,
      "uid": 1010251,
      "pid": 3254,
      "ts": 1793691792635,
      "host_received_ts": 1793691793683,
      "method": "POST",
      "request_started_ts": 1793691792625,
      "sensor_id": "battery_level",
      "state": 61,
      "status": 200,
      "body_complete": true
    }
  ],
  "independent_device_server_steps": [
    {
      "emulator_level": 73,
      "recorded_step_ms": 1793691791330,
      "server": {
        "state": "73",
        "last_changed": "2026-11-03T07:43:11.453048+00:00"
      }
    },
    {
      "emulator_level": 61,
      "recorded_step_ms": 1793691792744,
      "server": {
        "state": "61",
        "last_changed": "2026-11-03T07:43:12.631021+00:00"
      }
    }
  ]
}
```

## Home Assistant · 控制记录 1

- **W01** HTTP 成功回执、同连接订阅响应与独立服务端状态是否共同支持本轮两次控制？

```json
{
  "http": [
    {
      "src": "ha_transport",
      "evt_id": 3,
      "uid": 1010251,
      "pid": 3254,
      "ts": 1793711319107,
      "host_received_ts": 1793711320154,
      "method": "POST",
      "entity_id": "input_boolean.audit_test_light",
      "operation": "input_boolean.turn_on",
      "body_complete": true,
      "request_started_ts": 1793711318872,
      "status": 200
    },
    {
      "src": "ha_transport",
      "evt_id": 4,
      "uid": 1010251,
      "pid": 3254,
      "ts": 1793711321863,
      "host_received_ts": 1793711322927,
      "method": "POST",
      "entity_id": "input_boolean.audit_test_light",
      "operation": "input_boolean.turn_off",
      "body_complete": true,
      "request_started_ts": 1793711321845,
      "status": 200
    }
  ],
  "websocket": [
    {
      "src": "ha_socket",
      "evt_id": 2,
      "uid": 1010251,
      "pid": 3254,
      "ts": 1793711310717,
      "host_received_ts": 1793711311768,
      "ev": "HA_WS_SEND",
      "connection_id": 1,
      "message_id": 1976,
      "command": "subscribe_entities",
      "accepted": true
    },
    {
      "src": "ha_socket",
      "evt_id": 3,
      "uid": 1010251,
      "pid": 3254,
      "ts": 1793711310737,
      "host_received_ts": 1793711311775,
      "ev": "HA_WS_RESULT",
      "connection_id": 1,
      "message_id": 1976,
      "success": true
    },
    {
      "src": "ha_socket",
      "evt_id": 4,
      "uid": 1010251,
      "pid": 3254,
      "ts": 1793711315440,
      "host_received_ts": 1793711316481,
      "ev": "HA_WS_SEND",
      "connection_id": 2,
      "message_id": 1981,
      "command": "subscribe_entities",
      "accepted": true
    },
    {
      "src": "ha_socket",
      "evt_id": 5,
      "uid": 1010251,
      "pid": 3254,
      "ts": 1793711315448,
      "host_received_ts": 1793711316489,
      "ev": "HA_WS_RESULT",
      "connection_id": 2,
      "message_id": 1981,
      "success": true
    },
    {
      "src": "ha_socket",
      "evt_id": 6,
      "uid": 1010251,
      "pid": 3254,
      "ts": 1793711319071,
      "host_received_ts": 1793711320111,
      "ev": "HA_WS_STATE",
      "connection_id": 2,
      "message_id": 1981,
      "entity_id": "input_boolean.audit_test_light",
      "state": "on"
    },
    {
      "src": "ha_socket",
      "evt_id": 7,
      "uid": 1010251,
      "pid": 3254,
      "ts": 1793711321856,
      "host_received_ts": 1793711322922,
      "ev": "HA_WS_STATE",
      "connection_id": 2,
      "message_id": 1981,
      "entity_id": "input_boolean.audit_test_light",
      "state": "off"
    }
  ],
  "server_states": [
    {
      "start_ms": 1793711319816,
      "state": "on",
      "last_changed": "2026-11-03T13:08:39.048123+00:00"
    },
    {
      "start_ms": 1793711322804,
      "state": "off",
      "last_changed": "2026-11-03T13:08:41.854930+00:00"
    }
  ]
}
```

## Home Assistant · 控制记录 2

- **W02** 本轮是否有成功的 HTTP 控制回执？

```json
{
  "http": [
    {
      "src": "ha_transport",
      "evt_id": 2,
      "uid": 1010251,
      "pid": 3254,
      "ts": 1793691699548,
      "host_received_ts": 1793691700603,
      "method": "POST",
      "entity_id": "input_boolean.audit_test_light",
      "operation": "input_boolean.turn_on",
      "body_complete": true,
      "request_started_ts": 1793691699525,
      "status": 503
    }
  ],
  "websocket": [],
  "server_states": []
}
```

## MG4 · 表单记录 1

- **W03** 能否将服务端收到的 POST 绑定到目标应用发出的这一次请求？

```json
{
  "server_post_receipts": [
    {
      "method": "POST",
      "status": 200,
      "ts_ms": 1793691826284,
      "path": "/submit",
      "marker_ref": "marker-1",
      "body_ref": "body-1"
    }
  ],
  "app_request_events": [],
  "captured_proxy_flow_count": 0,
  "post_marker_matched_scope": "post_marker_matched 只表示 marker 出现在服务端收到的 POST 正文中；它不表示该请求已绑定到目标应用进程。绑定还需要 app_request_events 里的一条 App 侧事件，或一条归因成功的代理流；post_flow_attributed=0 时二者皆无。",
  "recorded_gaps": [
    "代理观察到 /submit POST，但缺少可验证的 App 身份与完整同值正文；WebView 网络进程映射待实测，按正文归因缺口登记。",
    "No sensitive API invocation was required by this browser workflow."
  ],
  "proxy_observed_post": true,
  "post_marker_matched": true,
  "post_flow_attributed": 0
}
```

## MG4 · 表单记录 2

- **W04** 能否用应用内请求的标记将服务端 POST 绑定到本次测试动作？

```json
{
  "server_post_receipts": [
    {
      "method": "POST",
      "status": 200,
      "ts_ms": 1793711783451,
      "path": "/submit",
      "marker_ref": "marker-1",
      "body_ref": "body-1"
    }
  ],
  "app_request_events": [
    {
      "src": "mg4_webview",
      "evt_id": 2,
      "uid": 1010252,
      "pid": 28856,
      "ts": 1793711782395,
      "host_received_ts": 1793711783435,
      "path": "/submit",
      "marker_ref": "marker-1"
    }
  ],
  "captured_proxy_flow_count": 0,
  "post_marker_matched_scope": "post_marker_matched 只表示 marker 出现在服务端收到的 POST 正文中；它不表示该请求已绑定到目标应用进程。绑定还需要 app_request_events 里的一条 App 侧事件，或一条归因成功的代理流；post_flow_attributed=0 时二者皆无。",
  "recorded_gaps": [
    "通过依据为替代关系：App 内 WebView POST 事件（src=mg4_webview）与服务端同值正文一致；代理逐流身份未核验（post_flow_attributed=0），不等同于代理逐流归因。",
    "No sensitive API invocation was required by this browser workflow."
  ],
  "attribution_basis": "webview_callback_and_server_body_substitution",
  "proxy_observed_post": true,
  "post_marker_matched": true,
  "post_flow_attributed": 0
}
```

## YAABSA · 播放进度

- **W05** 同一媒体会话的请求与服务端进度是否对齐，暂停后进度是否停止增长？

```json
{
  "wire_requests": [
    {
      "device_ts_ms": 1793712269169,
      "connection_port": 48504,
      "body_bytes": 59,
      "session_ref": "media-session-1",
      "body_ref": "body-1",
      "fields": {
        "currentTime": 5.0,
        "timeListened": 0.161028,
        "duration": 45.0
      }
    },
    {
      "device_ts_ms": 1793712274907,
      "connection_port": 48504,
      "body_bytes": 65,
      "session_ref": "media-session-1",
      "body_ref": "body-2",
      "fields": {
        "currentTime": 10.783698,
        "timeListened": 5.871496,
        "duration": 45.0
      }
    },
    {
      "device_ts_ms": 1793712274981,
      "connection_port": 48504,
      "body_bytes": 57,
      "session_ref": "media-session-1",
      "body_ref": "body-3",
      "fields": {
        "currentTime": 10.852,
        "timeListened": 0.0,
        "duration": 45.0
      }
    },
    {
      "device_ts_ms": 1793712289097,
      "connection_port": 51438,
      "body_bytes": 65,
      "session_ref": "media-session-1",
      "body_ref": "body-4",
      "fields": {
        "currentTime": 19.874652,
        "timeListened": 6.038361,
        "duration": 45.0
      }
    },
    {
      "device_ts_ms": 1793712289181,
      "connection_port": 51438,
      "body_bytes": 57,
      "session_ref": "media-session-1",
      "body_ref": "body-5",
      "fields": {
        "currentTime": 19.499,
        "timeListened": 0.0,
        "duration": 45.0
      }
    }
  ],
  "server_receipts": {
    "session_ref": "media-session-1",
    "progress_before": 5,
    "progress_after": 19.499,
    "listening_delta": 12.070885000000018,
    "pause_progress": 10.852,
    "progress_six_seconds_later": 10.852
  }
}
```

## YAABSA · 回环请求

- **W06** 应用写入与回环请求能否用端口、时间和正文标记逐条对应？

```json
{
  "wire_requests": [
    {
      "device_ts_ms": 1793694856040,
      "connection_port": 37608,
      "body_bytes": 65,
      "session_ref": "media-session-1",
      "body_ref": "body-1",
      "fields": {
        "currentTime": 36.151067,
        "timeListened": 6.051525,
        "duration": 45.0
      }
    },
    {
      "device_ts_ms": 1793694856086,
      "connection_port": 37608,
      "body_bytes": 57,
      "session_ref": "media-session-1",
      "body_ref": "body-2",
      "fields": {
        "currentTime": 36.178,
        "timeListened": 0.0,
        "duration": 45.0
      }
    }
  ],
  "app_socket_writes": [
    {
      "src": "abs_native_send",
      "evt_id": 2,
      "uid": 1010253,
      "pid": 2066,
      "ts": 1793694856043,
      "host_received_ts": 1793694857090,
      "local_port": 37608,
      "device_start_ms": 1793694856040,
      "device_end_ms": 1793694856043,
      "body_bytes": 65,
      "returned_bytes": 65,
      "write_size": 65,
      "session_ref": null,
      "body_ref": "body-1"
    },
    {
      "src": "abs_native_send",
      "evt_id": 3,
      "uid": 1010253,
      "pid": 2066,
      "ts": 1793694856086,
      "host_received_ts": 1793694857134,
      "local_port": 37608,
      "device_start_ms": 1793694856086,
      "device_end_ms": 1793694856086,
      "body_bytes": 57,
      "returned_bytes": 57,
      "write_size": 57,
      "session_ref": null,
      "body_ref": "body-2"
    }
  ]
}
```
