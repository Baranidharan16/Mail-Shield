import sys, time

submodules = [
    "app.forensic.engine",
    "app.ml.features",
    "app.ml.structured_model",
    "app.ml.text_model",
    "app.ai.fusion",
    "app.intel.enrichment",
    "app.intel.campaign",
    "app.intel.graph",
    "app.intel.attribution",
    "app.agent.investigation_agent",
    "app.blockchain.ledger",
]

for mod in submodules:
    t0 = time.time()
    print(f"Importing {mod}...", flush=True)
    __import__(mod)
    print(f"  Done in {time.time()-t0:.2f}s", flush=True)

print("ALL SUBMODULES IMPORTED!", flush=True)

