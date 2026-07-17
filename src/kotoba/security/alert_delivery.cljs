(ns kotoba.security.alert-delivery
  "Pluggable sinks for continuous-monitoring v1 alerts (R-005 pager wiring).

  Sinks (structured public alert maps only — never secrets):
  - file:    write EDN+JSON under a directory (default always-on)
  - webhook: POST JSON when KOTOBA_SECURITY_ALERT_WEBHOOK or explicit URL set
  - stdout:  print pretty JSON

  nbb/node helpers. CLI exit policy lives in scripts/emit-alert.cljs."
  (:require ["node:fs" :as fs]
            ["node:https" :as https]
            ["node:http" :as http]
            ["node:path" :as path]
            ["node:url" :as url]
            [clojure.string :as str]
            [kotoba.security.key-lifecycle :as kl]))

(defn alert->json
  [alert]
  (.stringify js/JSON (clj->js alert) nil 2))

(defn- ensure-dir!
  [dir]
  (when-not (fs/existsSync dir)
    (fs/mkdirSync dir #js {:recursive true})))

(defn deliver-file!
  "Write alert as EDN + JSON under dir. Returns {:ok? true :sink :file ...}."
  [alert dir]
  (ensure-dir! dir)
  (let [id (or (:alert/id alert) "alert")
        stem (-> id
                 (str/replace #"[^a-zA-Z0-9._-]+" "-")
                 (str/replace #"^-+" "")
                 (str/replace #"-+$" ""))
        edn-path (path/join dir (str stem ".edn"))
        json-path (path/join dir (str stem ".json"))]
    (fs/writeFileSync edn-path (pr-str alert))
    (fs/writeFileSync json-path (alert->json alert))
    (fs/appendFileSync (path/join dir "alerts.ndjson")
                       (str (.stringify js/JSON (clj->js alert)) "\n"))
    {:ok? true :sink :file :path edn-path :json-path json-path :dir dir}))

(defn deliver-stdout!
  [alert]
  (println (alert->json alert))
  {:ok? true :sink :stdout})

(defn deliver-webhook!
  "POST JSON alert to url. Returns a Promise of result map."
  [alert webhook-url]
  (js/Promise.
   (fn [resolve]
     (try
       (let [u (url/URL. webhook-url)
             body (alert->json alert)
             body-buf (js/Buffer.from body "utf8")
             is-https? (= "https:" (.-protocol u))
             lib (if is-https? https http)
             opts #js {:protocol (.-protocol u)
                       :hostname (.-hostname u)
                       :port (.-port u)
                       :path (str (.-pathname u) (or (.-search u) ""))
                       :method "POST"
                       :headers #js {"Content-Type" "application/json"
                                     "Content-Length" (str (.-length body-buf))
                                     "User-Agent" "kotoba-security-emit-alert/1"}}
             req (.request lib opts
                           (fn [res]
                             (let [chunks #js []]
                               (.on res "data" (fn [c] (.push chunks c)))
                               (.on res "end"
                                    (fn []
                                      (let [status (.-statusCode res)
                                            ok? (and status (>= status 200) (< status 300))]
                                        (resolve {:ok? ok?
                                                  :sink :webhook
                                                  :status status
                                                  :host (.-hostname u)
                                                  :path (.-pathname u)})))))))]
         (.on req "error"
              (fn [err]
                (resolve {:ok? false
                          :sink :webhook
                          :error (str err)
                          :host (try (.-hostname (url/URL. webhook-url))
                                     (catch :default _ "invalid-url"))})))
         (.write req body-buf)
         (.end req))
       (catch :default e
         (resolve {:ok? false :sink :webhook :error (str e)}))))))

(defn default-file-dir
  "Prefer evidence/<date>/alerts under repo root when evidence/ exists; else /tmp."
  [root date]
  (if (and root (fs/existsSync (path/join root "evidence")))
    (path/join root "evidence" date "alerts")
    "/tmp/kotoba-security-alerts"))

(defn build-alert
  [opts]
  (kl/emit-alert opts))

(defn deliver-sync-file-stdout!
  "Synchronous delivery for file + optional stdout. Returns results vector."
  [alert {:keys [file-dir stdout?]}]
  (cond-> [(deliver-file! alert file-dir)]
    stdout? (conj (deliver-stdout! alert))))

(defn deliver-all!
  "Deliver to file (required by default), optional webhook, optional stdout.
  Returns Promise {:ok? bool :results [...] :webhook-skipped? bool}."
  [alert {:keys [file-dir stdout? webhook no-file?]
          :or {stdout? false no-file? false}}]
  (let [env-wh (or webhook
                   (not-empty (.-KOTOBA_SECURITY_ALERT_WEBHOOK js/process.env)))
        sync-results (cond-> []
                       (not no-file?) (conj (deliver-file! alert file-dir))
                       stdout? (conj (deliver-stdout! alert)))
        webhook-skipped? (nil? env-wh)]
    (if env-wh
      (-> (deliver-webhook! alert env-wh)
          (.then (fn [wh]
                   (let [results (conj sync-results wh)
                         any-ok? (boolean (some :ok? results))]
                     {:ok? any-ok?
                      :results results
                      :webhook-skipped? false}))))
      (js/Promise.resolve
       {:ok? (boolean (some :ok? sync-results))
        :results sync-results
        :webhook-skipped? true}))))
