;;; -*- Mode: Lisp; Package: EDITOR -*-
;;;
;;; This file is not part of xyzzy.
;;;
; $Id: lib.l 753 2007-11-21 11:46:20Z torihat $
;
; ni/lib.l
;
; by HATTORI Masashi

(eval-when (:compile-toplevel :load-toplevel :execute)
  (require "ni/defs")
  (require "ni/macro"))

(provide "ni/lib")

(in-package "netinst")

(defun data-read-from-file (file)
  (let (data)
    (with-open-file (s
		     file
		     :direction :input
		     :if-does-not-exist :error)
      (let (tmp
	    #+multiple-frames (*read-eval* nil))
	(while (setq tmp (read s nil))
	  (push tmp data))))
    (nreverse data)))

(defun data-write-to-file (file data)
  (with-open-file (s
		   file
		   :direction :output
		   :if-exists :overwrite
		   :if-does-not-exist :create)
    (format s "~{~S~%~}" data))
  t)

(defun md5sum (file)
  (let (sum)
    (with-open-file (is file
			:direction :input
			:encoding :binary)
      (setq sum (si:md5 is)))
    sum))

(defun ni-message (fmt &rest args)
  (apply #'message (concat *prog-name* ": " fmt) args))

(defun ni-msgbox (fmt &rest args)
  (message-box (apply #'format nil fmt args)
	       *prog-name*))

(defun ni-error (fmt &rest args)
  (apply #'error (concat *prog-name* "~%" fmt) args))

(defun url-http-p (url)
  (string-match "^http://" url))

(defun url-https-p (url)
  (string-match "^https://" url))

(defun url-local-p (url)
  (or (string-match "^[a-zA-Z]:/" url)
      (string-match "^//" url)))

(defun url-to-filename (url)
  (cond ((url-http-p url)
	 (si:www-url-encode url))
	((url-https-p url)
	 (si:www-url-encode url))
	((url-local-p url)
	 url)
	(t
	 (ni-msgbox "URLâêÕïsî\: ~S" url))))

(defun string-length (str)
  (1- (si:chunk-size (si:make-string-chunk str))))

(defun reverse-line ()
  (clear-reverse-region)
  (reverse-region (progn (goto-eol) (point))
		  (progn (goto-bol) (point))))

(defun string-join (list &optional (expr " "))
  (let (str)
    (while list
      (if str
	  (setq str (concat str expr (car list)))
	(setq str (car list)))
      (setq list (cdr list))
      )
    str))

(defun open-in-browser (url)
  (shell-execute url t))

(defun check-read-time-eval (file)
  (let (result)
    (save-excursion
      (set-buffer (get-buffer-create *buffer-temp*))
      (unwind-protect
	  (progn
	    (erase-buffer (selected-buffer))
	    (insert-file-contents file)
	    (goto-char (point-min))
	    (when (scan-buffer "#." :regexp nil)
	      (setq result t)))
	(when (find-buffer *buffer-temp*)
	  (delete-buffer *buffer-temp*)))
      result)))
