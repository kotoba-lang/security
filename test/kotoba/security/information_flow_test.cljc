(ns kotoba.security.information-flow-test
  (:require [clojure.test :refer [deftest is]]
            [kotoba.security.information-flow :as flow]))

(deftest labels-propagate-by-lattice-join
  (is (= :confidential (flow/join [:public :confidential :internal])))
  (is (= :restricted (flow/join [:public nil]))))

(deftest downgrade-requires-an-exact-live-grant
  (let [request {:subject :did:alice :purpose :support
                 :now "2026-07-19T12:00:00Z"
                 :input-classifications [:confidential]
                 :output-classification :public}
        grant {:id :ticket-1 :subject :did:alice :purpose :support
               :from :confidential :to :public
               :expires-at "2026-07-19T13:00:00Z"}]
    (is (false? (:information-flow/allowed? (flow/evaluate-egress request))))
    (is (true? (:information-flow/allowed?
                (flow/evaluate-egress (assoc request :declassification-grant grant)))))
    (is (false? (:information-flow/allowed?
                 (flow/evaluate-egress
                  (assoc request :declassification-grant
                         (assoc grant :purpose :analytics))))))))
