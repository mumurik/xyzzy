;;; -*- Mode: Lisp; Package: EDITOR -*-
;;;
;;; This file is part of xyzzy.
;;;

(provide "about")

(in-package "editor")

(export 'about-dialog)

(let ((dialog-template nil))
  (defun about-dialog ()
    (interactive)
    (unless dialog-template
      (setq dialog-template
	    `(dialog 0 0 211 220
		     (:caption "‚É‚Â‚¢‚Ä")
		     (:font 9 "MS UI Gothic")
		     (:control
		      (:button IDOK "‚¨‚¯" #x50010001 171 7 33 14)
		      (:static nil nil #x50020003 7 7 18 20)
		      (:link xyzzy ,(concat "\001xyzzy\002 version "
					    (software-version-display-string))
		       #x50020000 34 7 123 8)
		      (:static nil "Copyright (C) 1996-2005 Tetsuya Kamei"
		       #x50020000 34 19 132 8)
		      (:link org "Copyright (C) 2012 \001xyzzy Project\002"
		       #x50020000 34 28 132 8)
		      (:static nil "Icon designed by 797@2ch xyzzy Part 17."
		       #x50020000 34 41 126 8)
		      (:static nil "RSA Data Security, Inc." #x50020000 34 52 83 8)
		      (:static nil "MD5 Message-Digest Algorithm." #x50020000 34 61 111 8)
		      (:listbox list  nil #x50a10111 34 72 170 60)
		      (:static nil "Šg’£lisp" #x50020000 34 140 111 8)
		      (:listbox lis   nil #x50a10111 34 150 170 60)))))
    (dialog-box dialog-template
		(list (cons 'list
			    (long-operation
			      (mapcan #'(lambda (x)
					  (let ((version (archiver-dll-version x)))
					    (and version
						 (list (list (get x 'archiver-dll-file-name)
							     version)))))
				      *archiver-dll-list*)))
		      (and (find-package "netinst")
			   (find-symbol "*install-data*" "netinst")
			   (cons 'lis
				 (mapcan #'(lambda (x)
					     (list
					      (list (cdr (assoc "name" x :test 'string=))
						    (cdr (assoc "version" x :test 'string=)))))
					 (sort (copy-list
						(or (symbol-value (find-symbol "*install-data*" "netinst"))
						    (funcall (find-symbol "load-install-data" "netinst"))))
					       #'string-lessp
					       :key #'(lambda (x) (cdr (assoc "name" x :test 'string=))))))))
		'((xyzzy :url "https://bitbucket.org/mumurik/xyzzy")
		  (org :url "https://bitbucket.org/mumurik/xyzzy")
		  (list :column (28 10))
		  (lis :column (28 10))))))
