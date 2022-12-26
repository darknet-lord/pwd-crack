(ns pwd-crack.core
  (:require [clojure.data.json :as json])
  (:require [clojure.java.io :as io])
  (:require [clojure.string :as string])
  (:require [clojure.walk :as walk])
  (:gen-class))

(import 'java.security.MessageDigest
                'java.math.BigInteger)

(def rules-file (io/resource "rules.json"))
(def words-file (io/resource "words.txt"))
(def load-rules (json/read-str (slurp rules-file)
                                :key-fn keyword))

(defn md5
  [^String pwd]
  (->> pwd
       .getBytes
       (.digest (MessageDigest/getInstance "MD5"))
       (BigInteger. 1)
       (format "%032x")))

(defn replace-with-special-ptrn [opts]
  (re-pattern (string/join "|" (for [k (keys (:replace_map opts))] (name k)))))

(def active-rules (filter (fn [rule] (= (get rule :enabled) true)) load-rules))

;; Rules
(defn rule-upcase-first [s opts] [(string/capitalize s)])
(defn rule-replace-with-special [s opts]
  [(string/replace s (replace-with-special-ptrn opts) (walk/stringify-keys (:replace_map opts)))])
(defn rule-prepend-special [s opts] (for [ch (:prefixes opts)] (str ch s)))
(defn rule-append-special [s opts] (for [ch (:suffixes opts)] (str s ch)))

(defn call [this & that]
  (apply (resolve (symbol this)) that))

(defn apply-rule [rule sentence]
  (call (string/join ["pwd-crack.core/rule-" (:name rule)]) sentence (:opts rule)))

(defn process-sentence [sentence pwdhash]
  (doseq [rule active-rules]
    (run! println (filter #(= % pwdhash) (map md5 (apply-rule rule sentence))))))

(defn find-hash [pwdhash]
   (with-open [rdr (clojure.java.io/reader words-file)]
     (doseq [line (line-seq rdr)]
       (process-sentence line pwdhash))))

(defn -main
  "Find the md5 hash match in the generated list of passwords: `lein run dc647eb65e6711e155375218212b3964`"
  [& args]
  (find-hash (first args)))
