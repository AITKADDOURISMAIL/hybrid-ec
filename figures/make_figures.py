import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
plt.rcParams.update({"font.size":9,"font.family":"serif","axes.spines.top":False,"axes.spines.right":False})
k=lambda u:u*0.5/1000  # units -> kcycles
C1,C2,C3="#1f77b4","#d95f02","#7f7f7f"

# Fig 1: fixed-base window
c_k=[4,5,6,7,8]; k1=[381119,350139,352191,409192,538024]
c_e=[3,4,5,6,7,8]; ed=[228378,193919,195946,225100,303061,449206]
fig,ax=plt.subplots(figsize=(3.4,2.4))
ax.plot(c_k,[k(v) for v in k1],"o-",color=C1,label="secp256k1")
ax.plot(c_e,[k(v) for v in ed],"s-",color=C2,label="Ed25519")
ax.set_xlabel("Window width $c$"); ax.set_ylabel("Cost (kcycles)"); ax.legend(frameon=False)
fig.tight_layout(); fig.savefig("fig_fixedbase.pdf"); fig.savefig("fig_fixedbase.png",dpi=200); plt.close(fig)

# Fig 2: optimization steps
fig,(a,b)=plt.subplots(1,2,figsize=(7.2,2.6),gridspec_kw={"width_ratios":[3,4]})
n=["Regular\n(reference)","wNAF\n($P_c$)","wNAF\n($P_s$)"]; v=[3733865,1120270,1277027]
a.bar(n,[k(x) for x in v],color=[C3,C2,C2]); a.set_title("Ed25519 verification"); a.set_ylabel("Cost (kcycles)")
n=["wNAF\n(no GLV)","GLV\n+ wNAF","BIP-340\nfull","ECDSA\nfull"]; v=[1223239,855556,1209749,1073649]
b.bar(n,[k(x) for x in v],color=[C3,C1,C1,C1]); b.set_title("secp256k1 verification")
for ax in (a,b):
    for p in ax.patches: ax.annotate(f"{p.get_height():.0f}",(p.get_x()+p.get_width()/2,p.get_height()),ha="center",va="bottom",fontsize=7)
fig.tight_layout(); fig.savefig("fig_steps.pdf"); fig.savefig("fig_steps.png",dpi=200); plt.close(fig)

# Fig 3: vs libraries
rows=[("Ed25519 $P_c$",1120270,[("dalek verify",245833),("zebra (ZIP-215)",327027)]),
      ("BIP-340",1209749,[("libsecp256k1",457432),("k256",677215)]),
      ("ECDSA",1073649,[("libsecp256k1",413514),("k256",716288)])]
fig,axs=plt.subplots(1,3,figsize=(6.8,2.2),sharex=False)
for ax,(t,ours,libs) in zip(axs,rows):
    names=["this work"]+[l[0] for l in libs]; vals=[k(ours)]+[k(l[1]) for l in libs]
    ax.barh(names[::-1],vals[::-1],color=[C3]*len(libs)+[C2]); ax.set_title(t,fontsize=9); ax.set_xlabel("kcycles")
    for y,x in enumerate(vals[::-1]): ax.text(x,y,f" {x:.0f}",va="center",fontsize=7)
    ax.set_xlim(0,max(vals)*1.25)
fig.tight_layout(); fig.savefig("fig_vs_libs.pdf"); fig.savefig("fig_vs_libs.png",dpi=200); plt.close(fig)

# Fig 4: batch verification (run5, per-signature cost and speedup)
U=[1,4,16,64,256,1024]
ours=[2081862,5034689,13626794,44365000,162177143,596586429]
ind=[1087589,4344737,17478230,71426794,286036516,None]
dal=[314115,726794,2600000,9862291,38577176,141051429]
zeb=[327033,748926,2572010,9686635,34680653,122319762]
ps=lambda x,u:x/u*0.5/1000
ind_ps=[ps(i,u) if i else None for i,u in zip(ind,U)]; ind_ps[5]=ind_ps[4]
fig,(a,b)=plt.subplots(1,2,figsize=(6.8,3.0))
a.plot(U,[ps(x,u) for x,u in zip(ours,U)],"o-",color=C2,label="this work (batch)")
a.plot(U,ind_ps,"o--",color=C3,label="this work (individual)")
a.plot(U,[ps(x,u) for x,u in zip(dal,U)],"s-",color=C1,label="ed25519-dalek (batch)")
a.plot(U,[ps(x,u) for x,u in zip(zeb,U)],"^-",color="#2ca02c",label="ed25519-zebra (batch)")
a.set_xscale("log",base=2); a.set_yscale("log"); a.set_xlabel("Batch size $u$"); a.set_ylabel("kcycles per signature"); a.legend(frameon=False,fontsize=6.5,loc="upper center",bbox_to_anchor=(0.5,-0.28),ncol=2)
b.plot(U,[ind_ps[i]/ps(ours[i],U[i]) for i in range(6)],"o-",color=C2,label="this work")
b.plot(U,[123/ps(x,u) for x,u in zip(dal,U)],"s-",color=C1,label="ed25519-dalek")
b.plot(U,[164/ps(x,u) for x,u in zip(zeb,U)],"^-",color="#2ca02c",label="ed25519-zebra")
b.axhline(1,color="k",lw=0.5); b.set_xscale("log",base=2); b.set_xlabel("Batch size $u$"); b.set_ylabel("Speedup $S(u)$"); b.legend(frameon=False,fontsize=7)
fig.tight_layout(); fig.savefig("fig_batch.pdf"); fig.savefig("fig_batch.png",dpi=200); plt.close(fig)

# Fig 5: block validation and failure scenario (run6)
Ns=[500,1000,3000,10000]
blk={"this work, individual":[562900476,1143814558,3380320000,11353457279],
     "this work, batch":[305386190,593949762,1712207381,5919010698],
     "ed25519-dalek, individual":[168607506,300699524,870288810,2935337947],
     "ed25519-dalek, batch":[69179286,135187907,387217184,1288896190],
     "ed25519-zebra, individual":[135486124,275752506,826460714,2766747255],
     "ed25519-zebra, batch":[63568095,126769412,355853095,1179875656]}
sty={"this work, individual":("o--",C3),"this work, batch":("o-",C2),"ed25519-dalek, individual":("s--","#9ecae1"),"ed25519-dalek, batch":("s-",C1),"ed25519-zebra, individual":("^--","#a1d99b"),"ed25519-zebra, batch":("^-","#2ca02c")}
fig,(a,b)=plt.subplots(1,2,figsize=(6.8,3.2),gridspec_kw={"width_ratios":[1.15,1]})
for n,v in blk.items():
    a.plot(Ns,[x*0.5/1e9 for x in v],sty[n][0],color=sty[n][1],label=n,ms=4)
a.set_xscale("log"); a.set_yscale("log"); a.set_xticks(Ns); a.set_xticklabels(Ns); a.set_xlabel("Transactions per block $N_{tx}$"); a.set_ylabel("Gcycles per block")
a.legend(frameon=False,fontsize=6,loc="upper center",bbox_to_anchor=(0.5,-0.25),ncol=2)
indiv={"this work":3380320000,"ed25519-dalek":870288810,"ed25519-zebra":826460714}
fail={"this work":[1723368258,5375872488,12850653488],"ed25519-dalek":[414630476,1253521053,2993458770],"ed25519-zebra":[358006190,1127880000,2368730788]}
import numpy as np
x=np.arange(3); w=0.26
for j,(n,col) in enumerate([("this work",C2),("ed25519-dalek",C1),("ed25519-zebra","#2ca02c")]):
    vals=[f/indiv[n] for f in fail[n]]
    bars=b.bar(x+(j-1)*w,vals,w,color=col,label=n)
    for r,v in zip(bars,vals): b.text(r.get_x()+r.get_width()/2,v,f"{v:.1f}",ha="center",va="bottom",fontsize=6)
b.axhline(1,color="k",lw=0.6); b.set_xticks(x); b.set_xticklabels(["$k=0$","$k=1$","$k=10$"]); b.set_ylabel("Batch + bisection / individual"); b.set_xlabel("Invalid signatures, $N_{tx}=3000$"); b.legend(frameon=False,fontsize=6.5,loc="upper left")
fig.tight_layout(); fig.savefig("fig_block.pdf"); fig.savefig("fig_block.png",dpi=200); plt.close(fig)
