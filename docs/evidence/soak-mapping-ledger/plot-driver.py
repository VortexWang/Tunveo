from pathlib import Path
import json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
base=Path('artifacts/mapping-ledger');data=json.loads((base/'independent-audit.json').read_text())['fixed'];rows=data['pilot']['coarse_runtime'];snap=data['pilot']['snapshots'];control=data['control']['snapshots'];M=1048576
fig,axes=plt.subplots(1,2,figsize=(12,4.8),layout='constrained')
x=[r['key'][1] for r in rows];known=[r['groups_rss_bytes'].get('observed_race_runtime',0)/M for r in rows];unknown=[r['groups_rss_bytes'].get('unresolved',0)/M for r in rows]
axes[0].stackplot(x,known,unknown,labels=['Observed runtime paths (whole VMA)','Unresolved'],colors=['#2563a8','#b9c0ca'],alpha=.9)
axes[0].axvline(12,color='#444',linestyle='--',linewidth=1);axes[0].text(12.3,3,'Measured phase',rotation=90,color='#444',fontsize=9)
axes[0].set(title='Go pilot: unnamed anonymous mappings only',xlabel='Native load clock (seconds)',ylabel='smaps RSS (MiB)');axes[0].legend(fontsize=8,loc='upper left');axes[0].grid(alpha=.2)
keys=['trace_switch','internal_allocator','mixed_allocators','unresolved'];colors=['#2563a8','#2c9866','#e39a32','#b9c0ca'];labels=['One trace context','Other context','Mixed whole VMA','Unresolved']
values={k:[] for k in keys}
for r in control:
 p=r['point'];lo=p['current'] if r['key'] in ('moved','released') else p['base'];hi=lo+(8 if r['key'] in ('moved','released') else 4)*M
 for key in keys:values[key].append(sum(v['rss'] for v in r['unnamed_vmas'] if lo<=v['start']<v['end']<=hi and v['owner']==key)/M)
bottom=[0]*len(control)
for key,color,label in zip(keys,colors,labels):
 axes[1].bar([r['key'] for r in control],values[key],bottom=bottom,color=color,label=label);bottom=[a+b for a,b in zip(bottom,values[key])]
axes[1].set(title='Real mapping control: no RSS prorating',ylabel='Controlled whole-VMA RSS (MiB)');axes[1].legend(fontsize=8);axes[1].grid(axis='y',alpha=.2)
fig.suptitle('Same-process mapping generations + syscall/RET context + monotonic smaps reads',fontsize=12)
fig.supxlabel('15-second pilot; 9 warmup/measured snapshots. Whole-VMA lower bounds, not live-object/leak proof.\nStatm budget uses separate reads. Mixed regions are never assigned proportionally to one caller.',fontsize=9)
fig.savefig(base/'mapping-rss.png',dpi=170)
