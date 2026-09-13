import time

def step(msg, fn):
    t0 = time.time()
    print(msg, flush=True)
    fn()
    print(f"  done in {time.time()-t0:.2f}s", flush=True)

step("1. import sklearn", lambda: __import__("sklearn"))
step("2. import scipy", lambda: __import__("scipy"))
step("3. import scipy.sparse", lambda: __import__("scipy.sparse"))
step("4. import sklearn.metrics", lambda: __import__("sklearn.metrics"))
step("5. import sklearn.feature_extraction", lambda: __import__("sklearn.feature_extraction"))
step("6. import sklearn.feature_extraction.text", lambda: __import__("sklearn.feature_extraction.text"))
print("ALL DONE!", flush=True)
