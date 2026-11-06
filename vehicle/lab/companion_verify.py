"""Offline verification of the companion's sanitized evidence handoff. 仅用于授权测试。"""
import argparse
import json
from pathlib import Path, PurePosixPath
from core.io_utils import load_jsonl
from vehicle.lab.abs_progress_run import link_positions
from vehicle.lab.abs_send_evidence import attribute_writes
from vehicle.pipeline.contracts import digest, read_json
from vehicle.pipeline.verify_bundle import verify


def verify_handoff(folder):
    folder=Path(folder).resolve()
    index=read_json(folder/'evidence-index.json')
    for row in index['files']:
        name=row['path'];parts=PurePosixPath(name)
        if parts.is_absolute() or '..' in parts.parts or '\\' in name or ':' in name:
            raise ValueError('unsafe evidence path')
        path=(folder/name).resolve()
        path.relative_to(folder)
        if not path.is_file() or digest(path)!=row['sha256']:
            raise ValueError('missing or modified artifact: '+name)
    audits={name:verify(folder/(name+'-audit')) for name in ('mg4','yaabsa')}
    if any(r['status']!='passed' for r in audits.values()): raise ValueError('audit bundle failed')
    capture=folder/'yaabsa-audit/bundle/capture'
    sealed=read_json(capture/'abs-syncs.json')
    reads=load_jsonl(capture/'reads.jsonl')
    links=attribute_writes(sealed['requests'],reads,**sealed['identity'])
    owner=sealed['identity']
    derived=link_positions(sealed['requests'],reads,links,owner['session'],owner['uid'],owner['serial'])
    business=read_json(folder/'cases/yaabsa/verification.json')
    keys=('request','write_link','position_refs','status')
    if [{k:r[k] for k in keys} for r in business['paired_requests']] != derived:
        raise ValueError('read/write evidence does not replay')
    if not business['passed'] or not all(business['checks'].values()):
        raise ValueError('native acceptance failed')
    browser=read_json(folder/'cases/mg4/business.json')
    if (browser['status']!='workflow_complete' or browser['post_flow_attributed']!=1
            or not browser['negative_control']['passed'] or not browser['capture_healthy']):
        raise ValueError('browser acceptance failed')
    return {'status':'passed','hashed_files':len(index['files']),
        'audit_files':{k:r['checked'] for k,r in audits.items()},
        'native_requests':len(derived),'read_write_candidates':sum(r['status']=='read_write_candidate' for r in derived),
        'manual_signoff':'pending','scoring':'workflow_only'}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder',type=Path)
    try:
        print(json.dumps(verify_handoff(parser.parse_args().folder),ensure_ascii=False))
    except (OSError,ValueError,KeyError,TypeError) as error:
        print(json.dumps({'status':'failed','error':str(error)},ensure_ascii=False))
        raise SystemExit(1)
