(eval-when (:compile-toplevel :load-toplevel :execute)
  (require "ni/update-xyzzy"))

(deftest safe-data-read ()
  "ni::safe-data-read が read-time-eval のリーダーマクロを実行しないことを確認。
   ni::load-site-data-file も同様の処理なのでこちらのテストは省略。"
  (with-temp-files (file)
    (with-open-file (out file :direction :output :if-does-not-exist :create)
      (format out "#.(+ 1 1)~%"))
    (ni::safe-data-read file))
  !! simple-error)
