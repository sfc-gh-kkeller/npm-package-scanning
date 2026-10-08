CREATE SERVICE IF NOT EXISTS BLESSED_NPM.REG.REGISTRY IN COMPUTE POOL BLESSED_NPM_POOL FROM SPECIFICATION $$
spec:
  containers:
  - name: registry
    image: /blessed_npm/reg/images/blessed-registry:latest
    env: {BLESSED_DIR: /blessed, PORT: "4873", RELOAD_MS: "30000"}
    volumeMounts:
    - {name: blessed, mountPath: /blessed}
    readinessProbe: {port: 4873, path: /healthz}
  endpoints:
  - {name: npm, port: 4873, public: true}   # true only to test the public-URL path; use false in production
  volumes:
  - {name: blessed, source: "@BLESSED_NPM.REG.BLESSED", uid: 1000, gid: 1000}
$$;
