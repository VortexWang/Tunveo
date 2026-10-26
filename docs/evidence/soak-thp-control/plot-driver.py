from pathlib import Path
import json,sys
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
base=Path('artifacts/thp-control');data=json.loads((base/'independent-audit.json').read_text())
fig,axes=plt.subplots(2,2,figsize=(11,8),layout='constrained')
for ax,(name,pair) in zip(axes.flat,sorted(data['cases'].items())):
 for case in pair['cases']:
  dest=base/name/'experiment'/(case['policy']+'-audit.json');audit=json.loads(dest.read_text())
  points=[p for p in audit['series'] if p['phase'].startswith('poststop')]
  color='#1769aa' if case['policy']=='default' else '#e07812'
  ax.plot([p['at_seconds'] for p in points],[p['statm_rss']/1048576 for p in points],color=color,marker='.',label=case['policy'])
  last=points[-1];ax.plot(last['at_seconds'],last['statm_rss']/1048576,marker='*',markersize=12,color=color)
 ax.set(title=name.removeprefix('thp-'),xlabel='Own post-stop clock (seconds)',ylabel='Process statm RSS (MiB)')
 ax.grid(alpha=.2);ax.legend(fontsize=9)
fig.suptitle('Same-VM sequential pilots: default vs Go-heap THP disabled',fontsize=14)
fig.supxlabel('Each arm is a fresh process; repeated GC during observation; stars: after ACK + FreeOSMemory.\nSeparate VMs/order groups; adjacent reads are not atomic. Resource failures remain failures.',fontsize=10)
fig.savefig(base/'thp-post-stop.png',dpi=160)
