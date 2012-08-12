;;; -*- Mode: Lisp; Package: EDITOR -*-
;;;
;;; This file is not part of xyzzy.
;;;
; $Id: local.l 734 2006-09-05 01:49:02Z torihat $
;
; ni/local.l
;
; by HATTORI Masashi

(eval-when (:compile-toplevel :load-toplevel :execute)
  (require "ni/defs")
  (require "ni/macro"))
(require "ni/lib")
(require "ni/apps")

(provide "ni/local")

(in-package "netinst")

(defvar *local-dist-url* nil)

(defun load-local-data ()
  (unless *local-data*
    (when (file-exist-p *local-data-file*)
      (setq *local-data*
	    (data-read-from-file *local-data-file*)))))

(defun format-packages()
  (interactive)
  (save-excursion
    (goto-line 5) ;; "packages". it might contain this string for author etc. So I use line number.
    (beginning-of-line)
    (search-forward "packages")
    (search-forward "(")
    (lisp-newline-and-indent)
    (goto-matched-parenthesis)
    (forward-char)
    (lisp-newline-and-indent)
    (while (looking-at "(")
      (goto-matched-parenthesis)
      (forward-char)
      (lisp-newline-and-indent))))
  

(defun save-local-data ()
  (data-write-to-file *local-data-file* *local-data*)
  (save-window-excursion
    (find-file *local-data-file*)
    (format-packages)
    (save-buffer)))

(defun create-site-data (&optional site)
  (list (cons "name" (site-name site))
	(cons "author" (site-author site))
	(cons "url" (site-url site))
	(cons "description" (site-description site))
	(cons "packages" (site-apps site))))

(defun create-app-data (&optional app)
  (list (cons "name" (app-name app))
	(cons "version" (app-version app))
	(cons "author" (app-author app))
	(cons "file" (app-file app))
	(cons "src" (app-src app))
	(cons "description" (app-description app))
	(cons "category" (app-category app))
	(cons "md5" (app-md5 app))
	(cons "time" (app-time app))
	(cons "depends" (app-depends app))
	(cons "changes" (app-changes app))
	(cons "notice" (app-notice app))
	(cons "load-after-install" (app-load-after-install app))
	(cons "load-before-uninstall" (app-load-before-uninstall app))
	))

(defun local-site-manage ()
  (interactive)
  (load-local-data)
  (unless *local-data*
    (setq *local-data* (create-site-data)))
  (setf (site-name *local-data*)
	(read-string "Site name: "
		     :default (site-name *local-data*)))
  (setf (site-author *local-data*)
	(read-string "Site author: "
		     :default (site-author *local-data*)))
  (setf (site-url *local-data*)
	(read-string "Site url: "
		     :default (site-url *local-data*)))
  (setf (site-description *local-data*)
	(read-string "Site description: "
		     :default (site-description *local-data*)))
  (save-local-data))

(defun local-app-xyzzy-add (&optional filename app-name)
  (interactive)
  (load-local-data)
  (unless *local-data*
    (ni-error "No site data."))
  (let* ((ignored-extensions
	  (remove ".lzh" ignored-extensions :test #'string-equal))
	 (apps (site-apps *local-data*))
	 (name "xyzzy")
	 (cur (local-app-get name))
	 (app (create-app-data cur))
	 (path (read-file-name "File: " :default filename))
	 (file (file-namestring path))
	 (files (mapcar 'car (list-archive path)))
	 (md5 (md5sum path))
	 (time (file-write-time path))
	 (version (read-string "App version: "
			       :default (app-version cur)))
	 (author "mumurik765")
	 (depends nil)
	 (description "xyzzy multiframe version")
	 (category nil)
	 (changes "")
	 (notice "")
	 (load-after-install "")
	 (load-before-uninstall "")
	 )
    (setf (app-name app) name)
    (setf (app-file app) file)
    (setf (app-src app)
	  (read-string "App src (url or path): "
		       :default (if cur
				    (app-src cur)
				  (if *local-dist-url*
				      (concat *local-dist-url* file)
				    path))))
    (setf (app-version app) version)
    (setf (app-md5 app) md5)
    (setf (app-time app) time)
    (setf (app-author app) author)
    (setf (app-depends app) depends)
    (setf (app-description app) description)
    (setf (app-category app) category)
    (setf (app-changes app) changes)
    (setf (app-notice app) notice)
    (setf (app-load-after-install app) load-after-install)
    (setf (app-load-before-uninstall app) load-before-uninstall)
    (setq apps
	  (remove-if #'(lambda (x)
			 (app-equal-p x app))
		     apps))
    (push app apps)
    (setf (site-apps *local-data*) apps)
    (save-local-data)))

(defun local-app-add (&optional filename app-name)
  (interactive)
  (load-local-data)
  (unless *local-data*
    (ni-error "No site data."))
  (let* ((ignored-extensions
	  (remove ".lzh" ignored-extensions :test #'string-equal))
	 (apps (site-apps *local-data*))
	 (name (local-app-select app-name))
	 (cur (local-app-get name))
	 (app (create-app-data cur))
	 (path (read-file-name "File: " :default filename))
	 (file (file-namestring path))
	 (files (mapcar 'car (list-archive path)))
	 (md5 (md5sum path))
	 (time (file-write-time path))
	 (version (read-string "App version: "
			       :default (app-version cur)))
	 (author (read-string "App author: "
			      :default (or (app-author cur)
					   (site-author *local-data*))))
	 (depends (local-app-select-depends (app-depends cur)))
	 (description (read-string "App description: "
				   :default (app-description cur)))
	 (category (local-app-select-category (app-category app)))
	 (changes (read-string "Recent changelog: "
			       :default (app-changes cur)))
	 (notice (read-string "Notice message: "
			      :default (app-notice cur)))
	 (load-after-install (completing-read "Load after install: "
					      files
					      :default (app-load-after-install cur)))
	 (load-before-uninstall (completing-read "Load before uninstall: "
						 files
						 :default (app-load-before-uninstall cur)))
	 )
    (setf (app-name app) name)
    (setf (app-file app) file)
    (setf (app-src app)
	  (read-string "App src (url or path): "
		       :default (if cur
				    (app-src cur)
				  (if *local-dist-url*
				      (concat *local-dist-url* file)
				    path))))
    (setf (app-version app) version)
    (setf (app-md5 app) md5)
    (setf (app-time app) time)
    (setf (app-author app) author)
    (setf (app-depends app) depends)
    (setf (app-description app) description)
    (setf (app-category app) category)
    (setf (app-changes app) changes)
    (setf (app-notice app) notice)
    (setf (app-load-after-install app) load-after-install)
    (setf (app-load-before-uninstall app) load-before-uninstall)
    (setq apps
	  (remove-if #'(lambda (x)
			 (app-equal-p x app))
		     apps))
    (push app apps)
    (setf (site-apps *local-data*) apps)
    (save-local-data)))

(defun local-app-select (&optional default must-match)
  (let* ((apps (site-apps *local-data*))
	 name)
    (completing-read "App name: "
		     (mapcar #'(lambda (x)
				 (app-name x))
			     apps)
		     :default default
		     :must-match must-match)))

(defun local-app-select-depends (&optional defaults)
  (let ((old (copy-seq defaults))
	depends
	(cur ""))
    (loop
      (setq cur (completing-read "Depends (\".\" to finish): "
				 old
				 :default (car old)))
      (cond ((equal cur ".")
	     (return))
	    ((string-match "^[ Å@\t\n]*$" cur)
	     nil)
	    (t
	     (pushnew cur depends :test #'equal)
	     (setq old (remove cur old :test #'equal)))))
    (nreverse depends)))

(defun local-app-select-category (&optional defaults)
  (let ((old (copy-seq defaults))
	categories
	(cur ""))
    (loop
      (setq cur (completing-read "Categories (\".\" to finish): "
				 *category-list*
				 :default (car old)))
      (cond ((equal cur ".")
	     (return))
	    ((member cur *category-list* :test #'equal)
	     (pushnew cur categories :test #'equal)
	     (setq old (remove cur old :test #'equal)))
	    (t
	     nil)))
    (nreverse categories)))

(defun local-read-lines (&optional default (name "Lines"))
  (let ((old (if default (split-string default "\n" t)))
	lines
	(cur "")
	def)
    (loop
      (setq def (car old))
      (setq old (cdr old))
      (setq cur (read-string (concat name " (\".\" to finish): ")
			     :default (if def def "")))
      (cond ((equal cur ".")
	     (return))
	    (t
	     (pushnew cur lines :test #'equal)
	     (setq old (remove cur old :test #'equal)))))
    (string-join (reverse lines) "\n")))

(defun local-app-delete (&optional name)
  (interactive)
  (load-local-data)
  (unless *local-data*
    (ni-error "No site data."))
  (let* ((apps (site-apps *local-data*))
	 app)
    (setq name (local-app-select name t))
    (when (setq app (local-app-get name))
      (setq apps (delete-if #'(lambda (x)
				(app-equal-p x app))
			    apps))
      (setf (site-apps *local-data*) apps)
      (save-local-data))))

(defun local-app-get (name)
  (let* ((apps (site-apps *local-data*)))
    (when apps
      (find-if #'(lambda (x)
		   (equal (app-name x) name))
	       apps))))
