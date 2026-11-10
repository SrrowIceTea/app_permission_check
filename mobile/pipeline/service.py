"""Pipeline service startup configuration. 仅用于授权测试。"""
import argparse
from pathlib import Path
from http.server import ThreadingHTTPServer
from mobile.pipeline import stages

def main() -> int:
    from mobile.pipeline.server import Registry, Handler, ROOT, DEFAULT_WORKDIR
    ap = argparse.ArgumentParser(description="移动应用完整检测服务（仅授权测试）")
    ap.add_argument("--port", type=int, default=8771)
    ap.add_argument("--workdir", default=DEFAULT_WORKDIR)
    ap.add_argument("--seconds", type=int, default=150,
                    help="默认钩子会话时长（秒）；上传时可用 ?seconds= 覆盖")
    ap.add_argument("--category", default="utility", help="默认类目 key")
    ap.add_argument("--tls-bypass", action="store_true",
                    help="对所有样本开启 TLS 校验收宽（默认关）。打开后传给 "
                         "device_run_thirdparty --tls-bypass → run.py --tls-bypass；"
                         "阶段日志里会打印 TLS_BYPASS=1。仅授权样本可用。")
    ap.add_argument("--audit-config", type=Path)
    ap.add_argument("--audit-selftest", type=Path)
    args = ap.parse_args()
    runtime = None
    if args.audit_config or args.audit_selftest:
        from mobile.workbench.runtime import Runtime
        from mobile.workbench.audit_inputs import configuration
        runtime = Runtime(Path(args.workdir) / "store", ROOT / "mobile/rules/rules_mobile.db", "36",
                          audit_config=args.audit_config, audit_selftest=args.audit_selftest)
        configuration(runtime)
    registry = Registry(Path(args.workdir), runtime)
    Handler.registry = registry
    # 默认参数挂到 handler，供 _upload 在未显式指定时回退
    Handler.defaults = {"seconds": args.seconds, "category": args.category,
                        "tls_bypass": bool(args.tls_bypass)}

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.daemon_threads = True
    print(f"一键审计流水线: http://127.0.0.1:{args.port}  （仅授权测试）")
    print(f"  产物目录: {registry.workdir}")
    print(f"  阶段数: {len(stages.STAGES)}；前端订阅 /api/pipeline/<id>/events")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n停止")
    finally:
        server.server_close()
        if runtime: runtime.close()
    return 0
