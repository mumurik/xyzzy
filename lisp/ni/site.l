;;; -*- Mode: Lisp; Package: EDITOR -*-
;;;
;;; This file is not part of xyzzy.
;;;
; $Id: site.l 752 2007-11-20 12:40:08Z torihat $
;
; ni/site.l
;
; by HATTORI Masashi

(eval-when (:compile-toplevel :load-toplevel :execute)
  (require "ni/defs")
  (require "ni/macro"))
(require "ni/lib")
(require "ni/local")
(require "ni/apps")
(require "ni/category")

(provide "ni/site")

(in-package "netinst")

(unless *site-map*
  (setq *site-map* (make-sparse-keymap))
  (define-key *site-map* #\RET 'site-apps-open)
  (define-key *site-map* #\SPC 'site-apps-open)
  (define-key *site-map* #\Right 'site-apps-open)
  (define-key *site-map* #\c 'category-show)
  (define-key *site-map* #\r 'site-update-current)
  (define-key *site-map* #\R 'site-update-all)
  (define-key *site-map* #\a 'site-add)
  (define-key *site-map* #\d 'site-del)
  (define-key *site-map* #\C-k 'site-cut)
  (define-key *site-map* #\C-y 'site-paste)
  (define-key *site-map* #\o 'site-open-in-browser)
  (define-key *site-map* #\q 'finish)
)

(defun site-mode ()
  (setq need-not-save t)
  (setq buffer-read-only t)
  (setq kept-undo-information nil)
  (setq auto-save nil)
  (set-local-window-flags (selected-buffer)
			  *window-flag-line-number* nil)
  (set-local-window-flags (selected-buffer)
			  *window-flag-newline* nil)
  (set-local-window-flags (selected-buffer)
			  *window-flag-eof* nil)
  (set-local-window-flags (selected-buffer)
			  *window-flag-cursor-line* t)
  (set-local-window-flags (selected-buffer)
			  *window-flag-vscroll-bar* nil)
  (set-local-window-flags (selected-buffer)
			  *window-flag-ruler* nil)
  (set-local-window-flags (selected-buffer)
			  *window-flag-just-inverse* t)
  (set-buffer-fold-width nil)
  (make-local-variable 'mode-line-format)
  (make-local-variable 'title-bar-format)
  (site-mode-line)
  (use-keymap *site-map*)
  (run-hooks '*ni-site-mode-hook*)
  )

(defun window-split ()
  (split-window-vertically *site-window-width*)
  (setq *window-site* (selected-window))
  (other-window 1)
  (setq *window-apps* (selected-window)))

(defun site-window-split ()
  (site-window-only)
  (window-split))

(defun site-window-only ()
  (interactive)
  (set-buffer-site)
  (delete-other-windows))

(defun set-buffer-site ()
  (set-buffer (get-buffer-create *buffer-site*)))

(defun site-mode-line ()
  (setq mode-line-format (format nil "%b"))
  (setq title-bar-format (format nil "%b")))

(defun site-mode-line-update ()
  (save-excursion
    (set-buffer-site)
    (site-mode-line)))

(defun site-data-file (site)
  (merge-pathnames (concat (url-to-filename (site-src site))) *data-directory*))

(defun get-site-data (site &optional force)
  (let ((src (site-src site))
	(file (site-data-file site)))
      (http-get-to-file src file force)))

(defun load-site-data-file (site)
  (let ((file (site-data-file site)))
    (when (file-exist-p file)
      (when (check-read-time-eval file)
	(ni-error "不正なファイルです: ~%~A" file))
      (data-read-from-file file))))

(defun setup-default-app-data()
  (when *initial-site-url*
    (update-site *initial-site-url*
		 (site-create *initial-site-url*)
		 0)))

(defun setup-app-data-from-sites(sites-temp)
  (let (sites)
    (dolist (site sites-temp)
      (handler-case
	  (let ((data (load-site-data-file site)))
	    (when data
	      (unless (site-src data)
		(push (cons "src" (site-src site)) data))
	      (push data sites)
	      (dolist (app (site-apps data))
		(setq app (app-data-add-site app data))
		(push app *app-data*))))
	(error (c)
	  (ni-msgbox "Error:~%~A" (si:*condition-string c)))))
    (setq *app-data*
	  (sort *app-data* #'app-newer-p))
    (nreverse sites)))

(defun load-site-data ()
  (let (sites-temp)
    (when (file-exist-p *install-site-file*)
      (setq sites-temp
	    (data-read-from-file *install-site-file*)))
    (setq *app-data* nil)
    (if sites-temp
	(setq *site-data* (setup-app-data-from-sites sites-temp))
      (setup-default-app-data))
    (category-parse)
    (save-site-data)))

(defun save-site-data ()
  (data-write-to-file *install-site-file* *site-data*))

(defun site-print ()
  (modify-read-only-buffer
   (erase-buffer (selected-buffer))
   (clear-all-text-attributes)
   (apply #'set-text-attribute
	  (point)
	  (progn
	    (insert (format nil "ALL Sites (~D)~%" (length *app-data*)))
	    (point))
	  'sites
	  *attribute-site-all*)
   (dolist (site *site-data*)
     (let ((name (site-name site)))
       (apply #'set-text-attribute
	      (point)
	      (progn
		(insert (format nil " ~A (~D)~%" name (length (site-apps site))))
		(point))
	      'site
	      *attribute-site*)))
   (goto-char (point-min)))
  (run-hooks '*ni-site-print-hook*))

(defvar *site-line-diff* 2)

(defun site-line-to-number (line-number)
  (- line-number *site-line-diff*))

(defun site-number-to-line (pos)
  (+ pos *site-line-diff*))

(defun site-current ()
  (let ((num (current-line-number)))
    (cond ((= 1 num)
	   nil)
	  ((< 1 num)
	   (nth (site-line-to-number num) *site-data*))
	  (t
	   nil))))

(defun site-delete (pos)
  (let ((len (length *site-data*))
	temp)
    (when (<= len pos)
      (return-from site-delete))
    (dotimes (i len)
      (unless (= i pos)
	(push (nth i *site-data*) temp)))
    (setq *site-data* (nreverse temp))
    (save-site-data)))

(defun delete-site-file (site)
  (let ((file (site-data-file site)))
    (when (and (file-exist-p file)
	       (yes-or-no-p "取得したファイルを削除しますか？"))
      (delete-file file))))

(defun site-insert (site &optional pos)
  (let ((len (length *site-data*))
	temp)
    (setq pos (if pos
		  (min pos len)
		len))
    (dotimes (i len)
      (when (= i pos)
	(push site temp))
      (push (nth i *site-data*) temp))
    (when (= pos len)
      (push site temp))
    (setq *site-data* (nreverse temp))
    (save-site-data)))

(defun site-create (src)
  (let ((site (create-site-data)))
    (push (cons "src" src) site)
    site))

(defvar *site-temp-buffer-suffix* "TEMPORARY")

(defun set-site-data (key val site)
  (if (site-value key site)
      (setf (site-value key site) val)
    (push (cons key val) site))
  site)

(defun site-exist-p (url)
  (assoc-if #'(lambda (x)
		(equal url (site-url x)))
	    *site-data*))

(defun update-site (src site pos)
  (get-site-data site)
  (let ((site (load-site-data-file site)))
    (unless site
      (ni-error "データを取得できません。"))
    (setq site (set-site-data "src" src site))
    (site-insert site (max pos 0)))
  (save-site-data)
  (load-site-data))

(defun site-add (src)
  (interactive "sURL: ")
  (let* ((temp (site-create src))
	 (num (current-line-number))
	 (pos (site-line-to-number num))
	 name
	 description)
    (when (site-exist-p src)
      (ni-error "すでに存在します: ~A" src))
    (update-site src temp pos)
    (site-print)
    (goto-line num)))

(defun site-del ()
  (interactive)
  (let ((num (current-line-number))
	(pos (site-line-to-number (current-line-number)))
	(site (site-current)))
    (when site
      (site-delete pos)
      (delete-site-file site)
      (save-site-data)
      (load-site-data)
      (site-print)
      (goto-line num))))

(defun clipboard-push (site)
  (push site *site-clipboard*))

(defun clipboard-pop ()
  (pop *site-clipboard*))

(defun site-cut ()
  (interactive)
  (let* ((num (current-line-number))
	 (pos (site-line-to-number num))
	 (site (site-current)))
    (when site
      (site-delete pos)
      (clipboard-push site)
      (load-site-data)
      (site-print)
      (goto-line num))))

(defun site-paste ()
  (interactive)
  (let* ((num (current-line-number))
	 (pos (site-line-to-number num))
	 (site (clipboard-pop)))
    (when site
      (site-insert site pos)
      (load-site-data)
      (site-print)
      (goto-line num))))

(defun site-update-current ()
  (interactive)
  (let ((num (current-line-number))
	(site (site-current)))
    (unless site
      (return-from site-update-current))
    (reverse-line)
    (refresh-screen)
    (site-update-data site)
    (clear-reverse-region)
    (load-site-data)
    (site-print)
    (goto-line num)
    (site-apps-open)))

(defun site-update-all ()
  (interactive)
  (let (errors)
    (dotimes (i (length *site-data*))
      (let ((line (site-number-to-line i))
	    (site (nth i *site-data*)))
	(goto-line line)
	(reverse-line)
	(refresh-screen)
	(handler-case
	    (site-update-data site)
	  (error (c)
	    (push (format nil "Error: ~S:~%~A"
			  (site-name site)
			  (si:*condition-string c))
		  errors)))
	(do-events)))
    (clear-reverse-region)
    (load-site-data)
    (site-print)
    (goto-line 1)
    (if errors
	(ni-error "~{~A~%~}" (reverse errors))
      (site-apps-open))
    ))

(defun site-update-data (site)
  (let (new)
    (get-site-data site t)
    (setq new (load-site-data-file site))
    (if (equal site new)
	nil
      (progn
	(unless (equal (site-name site)
		       (site-name new))
	  (modify-installed-site-name site new))
	t))))

(defun site-apps-open ()
  (interactive)
  (let* ((site (site-current))
	 (apps (if site
		   (apps-of-site site)
		 *app-data*)))
    (site-window-split)
    (apps-open apps)
    (goto-line 1))
  (run-hooks '*ni-site-apps-open-hook*))

(defun apps-of-site (site)
  (sort (mapcar #'(lambda (x)
		    (app-data-add-site x site))
		(site-apps site))
	#'app-newer-p))

(defun app-data-add-site (app site)
  (unless (app-author app)
    (push (cons "author" (site-author site)) app))
  (unless (app-site app)
    (push (cons "site" (site-name site)) app))
  app)

(defun site-open-in-browser ()
  (interactive)
  (let* ((site (site-current))
	 (url (site-url site)))
    (when url
      (open-in-browser url))))
