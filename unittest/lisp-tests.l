(deftest fix-previous-pseudo-frame-test ()
  "(previous-pseudo-frame) caused \"appframe not found\" error."
  (previous-pseudo-frame)
  => nil)


;; (make-frame) create strange scratch buffer
;(deftest fix-multiframe-create-strange-buffer-test ()
;; make frame asis cause split-window problem.
;; So I comment out this test now.
(defun dummy-fix-multiframe-create-strange-buffer-test ()
  (let* ((org (length (buffer-list)))
	 frame res)
    (setq frame (make-frame))
    (setq res (= org (length (buffer-list))))
    ;; changing selected-frame cause problem.
    ;; (delete-frame frame)
    res)
  => t)

(defun make-test-package (&rest options)
  (let ((name (format nil "temporary-package-for-test-~D" (test-uid))))
    (apply #'make-package name options)))

(deftest fix-list-all-packages-test ()
  "(list-all-packages) should return 'a copy of' system package list."
  (let* ((pkg (make-test-package))
         (name (package-name pkg))
	 (pkglist (list-all-packages)))
    (delete pkg pkglist)
    (eq pkg (find-package name)))
  => t)

(defmacro with-moved-p (&body body)
  `(let* ((#1=#:point (point)))
     (save-excursion
       ,@body
       (not (eq #1# (point))))))

(defmacro with-c++-bed (&body body)
  `(with-temp-buffer
    (c++-mode)
    ,@body
    ))

(defun setup-text(text)
  (insert text)
  (goto-char 0))

(deftest fix-parenthesis-escape-case-forward ()
  "cc mode goto-matched parentheis does not understand escape for hanlding comment"
  (with-c++-bed
   (setup-text "(hoge\\//)")
   (with-moved-p
    (goto-matched-parenthesis)))
  => t)

(deftest fix-parenthesis-escape-case-backward ()
  "cc mode goto-matched parentheis does not understand escape for hanlding comment, backward"
  (with-c++-bed
   (setup-text "(hoge\\//)")
   (search-forward ")")
   (with-moved-p
    (goto-matched-parenthesis)))
  => t)

(deftest fix-parenthesis-no-escape-case-forward ()
  "cc mode goto-matched parentheis does not understand escape for hanlding comment, not escape case"
  (with-c++-bed
   (setup-text "(hoge\\\\//)")
   (with-moved-p
    (goto-matched-parenthesis)))
  => nil)

(deftest fix-parenthesis-no-escape-case-backward ()
  "cc mode goto-matched parentheis does not understand escape for hanlding comment, not escape case, backward"
  (with-c++-bed
   (setup-text "(hoge\\\\//)")
   (search-forward ")")
   (with-moved-p
    (goto-matched-parenthesis)))
  => nil)

;;; Test scroll-other-window or similar functions.
;;; When there is only one window, they should not raise an error.
(deftest fix-scroll-other-window-test ()
  "(scroll-other-window) shouldn't raise an error
even if there is only one window."
  (save-window-excursion
    (delete-other-windows)
    (handler-case
	(progn (scroll-other-window) t)
      (range-error (c) nil))))

(deftest fix-scroll-up-other-window-test ()
  "(scroll-up-other-window) shouldn't raise an error
even if there is only one window."
  (save-window-excursion
    (delete-other-windows)
    (handler-case
	(progn (scroll-up-other-window) t)
      (range-error (c) nil))))

(deftest fix-scroll-down-other-window-test ()
  "(scroll-down-other-window) shouldn't raise an error
even if there is only one window."
  (save-window-excursion
    (delete-other-windows)
    (handler-case
	(progn (scroll-down-other-window) t)
      (range-error (c) nil))))

(deftest fix-scroll-up-both-window-test ()
  "(scroll-up-both-window) shouldn't raise an error
even if there is only one window."
  (save-window-excursion
    (delete-other-windows)
    (handler-case
	(progn (scroll-up-both-window) t)
      (range-error (c) nil))))

(deftest fix-scroll-down-both-window-test ()
  "(scroll-down-both-window) shouldn't raise an error
even if there is only one window."
  (save-window-excursion
    (delete-other-windows)
    (handler-case
	(progn (scroll-down-both-window) t)
      (range-error (c) nil))))
