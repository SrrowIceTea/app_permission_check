"""Native AAOS playback read/write/receipt acceptance. 仅用于授权测试。"""
import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from core.io_utils import load_jsonl
from vehicle.lab.abs_api import request
from vehicle.lab.abs_send_evidence import attribute_writes
from vehicle.lab.ui import UI
from vehicle.pipeline.capture_device import wait_until
from vehicle.pipeline.contracts import ROOT, digest, read_json, write_json
from vehicle.pipeline.preflight import validate_capture
from vehicle.privacy.abs_contract import PACKAGE, APK_SHA256


def within_period(row, step):
    return step['start_device_ms'] <= row['device_ts_ms'] <= step['end_device_ms']


def link_positions(requests, reads, links, session, uid, serial='emulator-5554'):
    owned=[r for r in reads if r.get('session_id')==session and r.get('pkg')==PACKAGE
           and r.get('uid')==uid and r.get('user_id')==10 and r.get('device_serial')==serial]
    writes={r['evt_id']:r for r in owned if r.get('src')=='abs_native_send'}
    values=[r for r in owned if r.get('src')=='abs_progress' and r.get('ev')=='ABS_POSITION'
        and r.get('session_id')==session and r.get('pkg')==PACKAGE and r.get('uid')==uid
        and r.get('user_id')==10 and r.get('api')=='yc.d.S()J'
        and type(r.get('position_ms')) is int and r['position_ms']>=0]
    out=[]
    for row,link in zip(requests,links,strict=True):
        candidates=[]
        if link['status']=='uid_verified':
            event=writes[link['write_refs'][0]['evt_id']]
            candidates=[r for r in values if r.get('pid')==event['pid']
                and 0 <= event['device_start_ms']-r['ts'] <= 30000
                and abs(r['position_ms']-row['body']['currentTime']*1000)<=2000]
        out.append({'request':row,'write_link':link,
            'position_refs':[{'src':'abs_progress','evt_id':r['evt_id'],'position_ms':r['position_ms']}
                             for r in candidates],
            'status':'read_write_candidate' if candidates else 'read_write_gap'})
    return out


def run(out,folder,apk,serial):
    out.mkdir(parents=True,exist_ok=False)
    ui=UI(out/'ui',serial);device=ui.device
    result={'passed':False,'scope':'native_aaos_pinned_yaabsa_isolated_http','scoring':'workflow_only','steps':[]}
    worker=log=button=None;capture=out/'capture'
    def device_now():
        stamp=device.call('shell','date','+%s%3N')
        if not re.fullmatch(r'\d{13}',stamp): raise ValueError('device millisecond clock unavailable')
        return int(stamp)
    try:
        identity=device.ordinary_identity(PACKAGE,10,'general')
        if digest(apk)!=APK_SHA256 or identity['installed_apk_sha256']!=APK_SHA256:
            raise ValueError('pinned installed APK required')
        result['identity']=identity
        library=read_json(folder/'abs-library.json')
        items=library['items']
        if len(items)!=1: raise ValueError('expected exactly one owned synthetic book')
        item=items[0]['id']
        creds=read_json(folder/'abs-test-credentials.private.json')
        logged=request('/login',{k:creds[k] for k in ('username','password')})['user']
        token=logged.get('accessToken') or logged['token']
        def state():
            progress=request('/api/me/progress/'+item,token=token)
            sessions=request('/api/me/listening-sessions?itemsPerPage=20',token=token)['sessions']
            return {'progress':{'currentTime':progress.get('currentTime')},
                'sessions':[{k:s.get(k) for k in ('id','libraryItemId','timeListening','updatedAt')}
                            for s in sessions if s.get('libraryItemId')==item]}
        device.call('shell','am','start','--user',10,'-W','-a','android.car.intent.action.MEDIA_TEMPLATE',
                    '-e','android.car.intent.extra.MEDIA_COMPONENT',PACKAGE+'/com.ryanheise.audioservice.AudioService')
        time.sleep(3)
        media=device.call('shell','dumpsys','media_session')
        if 'state=PAUSED(2)' not in media: raise ValueError('prepare owned media in paused state using its UI')
        baseline=state()
        result['baseline']=baseline
        screen=ui.snapshot('00-paused-start')
        bars=[n for n in screen.iter('node') if n.get('resource-id')=='com.android.car.media:id/playback_seek_bar']
        if len(bars)!=1: raise ValueError('owned native media player seekbar required')
        bounds=list(map(int,re.findall(r'\d+',bars[0].get('bounds',''))))
        buttons=[n for n in screen.iter('node') if n.get('resource-id')=='com.android.car.media:id/play_pause_container']
        if len(buttons)!=1: raise ValueError('native play/pause control required')
        button=buttons[0]
        def seek(fraction):
            x=round(bounds[0]+fraction*(bounds[2]-bounds[0]));y=(bounds[1]+bounds[3])//2
            device.call('shell','input','-d','0','tap',x,y)
        seek(.15)
        log=(out/'capture.log').open('w',encoding='utf-8')
        worker=subprocess.Popen([sys.executable,'-m','vehicle.pipeline.capture','--package',PACKAGE,
            '--serial',serial,'--user','10','--scope','general','--preserve-system-proxy',
            '--abs-send','--seconds','110','--out',str(capture)],cwd=ROOT,stdout=log,stderr=log)
        def ready():
            if worker.poll() is not None: raise RuntimeError('capture exited before ready')
            return '"status": "capturing"' in (out/'capture.log').read_text(encoding='utf-8')
        wait_until(ready,40,'YAABSA capture')
        for label,fraction in [('foreground',.15),('background',.55)]:
            if label=='background': seek(fraction)
            time.sleep(1)
            ui.tap_node(button)
            wait_until(lambda:'state=PLAYING(3)' in device.call('shell','dumpsys','media_session'),5,'actual playback')
            if label=='background': device.call('shell','input','keyevent',3)
            start=device_now()
            activities=device.call('shell','dumpsys','activity','activities')
            (out/(label+'-activities.txt')).write_text(activities,encoding='utf-8')
            media=device.call('shell','dumpsys','media_session')
            (out/(label+'-playing.txt')).write_text(media,encoding='utf-8')
            if 'package='+PACKAGE not in media or 'state=PLAYING(3)' not in media:
                raise ValueError('actual playback not confirmed')
            time.sleep(14)
            during=state()
            end=device_now()
            if label=='background':
                device.call('shell','am','start','--user',10,'-W','-a','android.car.intent.action.MEDIA_TEMPLATE',
                    '-e','android.car.intent.extra.MEDIA_COMPONENT',PACKAGE+'/com.ryanheise.audioservice.AudioService')
                time.sleep(.5)
            ui.tap_node(button)
            time.sleep(3)
            media=device.call('shell','dumpsys','media_session')
            (out/(label+'-paused.txt')).write_text(media,encoding='utf-8')
            if 'state=PAUSED(2)' not in media: raise ValueError('actual pause not confirmed')
            receipt=state()
            result['steps'].append({'name':label,'start_device_ms':start,'end_device_ms':end,
                'post_pause_device_ms':device_now(),'server_during_playback':during,
                'server_after_pause':receipt,'seek_fraction':fraction,
                'activity_confirmed':bool(re.search(r'topResumedActivity=.*u10 '+
                    ('com.android.car.carlauncher/' if label=='background' else 'com.android.car.media/'),activities))})
            if label=='foreground':
                paused=receipt['progress']['currentTime']
                time.sleep(6)
                again=state()['progress']['currentTime']
                result['negative_control']={'kind':'actual_media_pause','first':paused,'again':again,
                    'passed':type(paused) in (int,float) and type(again) in (int,float) and abs(paused-again)<.5,
                    'permission_denial':'not_tested'}
        (capture/'.finish-request').touch()
        result['capture_exit']=worker.wait(timeout=60)
        if result['capture_exit']!=0: raise RuntimeError('capture health failed')
        valid=validate_capture(capture,PACKAGE,'15',ROOT/'vehicle/rules/rules_library/rules.db',apk)
        reads=load_jsonl(capture/'reads.jsonl')
        sealed=read_json(capture/'abs-syncs.json')
        links=attribute_writes(sealed['requests'],reads,**sealed['identity'])
        paired=link_positions(sealed['requests'],reads,links,valid['session_id'],sealed['identity']['uid'],serial)
        after=state()
        previous={s['id']:s for s in baseline['sessions']}
        aligned=[]
        for row in paired:
            s=next((s for s in after['sessions'] if s['id']==row['request']['session_id']),None)
            row['independent_session_receipt']=s
            if s and row['status']=='read_write_candidate': aligned.append(row)
        for step in result['steps']:
            step['read_write_requests']=[r for r in aligned if step['start_device_ms']<=
                r['request']['device_ts_ms']<=step['post_pause_device_ms']]
            # Return-to-player pause reads are explicitly outside the background period.
            step['business_requests']=[r for r in sealed['requests'] if within_period(r,step)]
            current=step['server_during_playback']['progress']['currentTime']
            step['live_receipt_matches']=any(type(current) in (int,float) and
                abs(r['body']['currentTime']-current)<.001 for r in step['business_requests'])
        listened=sum(r['body']['timeListened'] for r in sealed['requests'])
        ids={r['session_id'] for r in sealed['requests']}
        delta=sum(float(s.get('timeListening') or 0)-float(previous.get(s['id'],{}).get('timeListening') or 0)
                  for s in after['sessions'] if s['id'] in ids)
        result.update(session=valid['session_id'],paired_requests=paired,server_after=after,
            request_time_listened=listened,server_time_listened_delta=delta)
        positive=all(s['read_write_requests'] for s in result['steps'])
        distinct=abs(float(result['steps'][1]['server_after_pause']['progress']['currentTime'])-
                     float(result['steps'][0]['server_after_pause']['progress']['currentTime']))>5
        result['checks']={'two_value_read_write_receipt':bool(positive and distinct),
            'pause_control':result['negative_control']['passed'],
            'independent_increment':listened>0 and delta>0 and abs(delta-listened)<=2,
            'capture_healthy':read_json(capture/'verification.json')['passed']}
        result['checks']['foreground_background_business']=all(
            s['activity_confirmed'] and s['live_receipt_matches'] for s in result['steps'])
        result['read_scope']='two pause-time API returns; periodic background progress may be extrapolated and stays a read gap'
        result['passed']=all(result['checks'].values())
    except Exception as error:
        result['error']=error.record() if hasattr(error,'record') else {'type':type(error).__name__,'message':str(error)}
    finally:
        try:
            if button is not None and 'state=PLAYING(3)' in device.call('shell','dumpsys','media_session'):
                device.call('shell','am','start','--user',10,'-W','-a','android.car.intent.action.MEDIA_TEMPLATE',
                    '-e','android.car.intent.extra.MEDIA_COMPONENT',PACKAGE+'/com.ryanheise.audioservice.AudioService')
                time.sleep(.5);ui.tap_node(button)
        except Exception:
            result['playback_cleanup_failed']=True;result['passed']=False
        if worker and worker.poll() is None:
            if capture.exists(): (capture/'.finish-request').touch()
            try: worker.wait(timeout=60)
            except subprocess.TimeoutExpired:
                worker.terminate();worker.wait(timeout=5);result['forced_stop']=True;result['passed']=False
        if log: log.close()
        write_json(out/'verification.json',result)
    return result['passed']


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True);parser.add_argument('--folder',type=Path,required=True)
    parser.add_argument('--apk',type=Path,required=True);parser.add_argument('--serial',default='emulator-5554')
    args=parser.parse_args()
    raise SystemExit(0 if run(args.out.resolve(),args.folder.resolve(),args.apk.resolve(),args.serial) else 1)
