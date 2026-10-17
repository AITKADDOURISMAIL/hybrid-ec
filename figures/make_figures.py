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
