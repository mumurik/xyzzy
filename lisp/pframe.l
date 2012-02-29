;;; -*- Mode: Lisp; Package: EDITOR -*-
;;;
;;; This file is part of xyzzy.
;;;

(provide "pframe")

(in-package "editor")

(export '(find-pseudo-frame new-pseudo-frame select-pseudo-frame
	  other-pseudo-frame delete-pseudo-frame ctl-x-6-prefix
	  ctl-x-6-map next-pseudo-frame previous-pseudo-frame
	  delete-all-pseudo-frames rename-pseudo-frame
	  get-current-pseudo-frame
	  selected-pseudo-frame-name
	  get-pseudo-frame-list
	  selected-pseudo-frame *select-pseudo-frame-hook*
	  switch-pseudo-frame pseudo-frame-selector))

(defstruct
  (pseudo-frame (:constructor pseudo-frame-constructor
		 (name winconf save-p selected-fn deleted-fn)))
  name winconf save-p selected-fn deleted-fn)

(defvar *pseudo-frame-counter* 1)
(defvar *current-pseudo-frame* (make-hash-table))
(defvar *pseudo-frame-list* (make-hash-table))
(defvar *select-pseudo-frame-hook* nil)

(generate-hash-accessor current-pseudo-frame)
(generate-hash-accessor pseudo-frame-list)

(defun selected-pseudo-frame-name()
  (pseudo-frame-name (selected-pseudo-frame)))

(defun selected-pseudo-frame ()
  (get-current-pseudo-frame (selected-frame)))

(defun save-current-pseudo-frame (&optional (appframe (selected-frame)))
  (when (get-current-pseudo-frame appframe)
    (setf (pseudo-frame-winconf (get-current-pseudo-frame appframe))
	  (current-window-configuration appframe))))

(defun find-pseudo-frame (name &optional (appframe (selected-frame)))
  (find name (get-pseudo-frame-list appframe)
	:key #'pseudo-frame-name :test #'string=))

(defun pseudo-frame-check-minibuffer (appframe)
  (when (window-buffer (minibuffer-window appframe))
    (when (tool-bar-exist-p 'pseudo-frame-bar appframe)
      (tab-bar-select-item 'pseudo-frame-bar (get-current-pseudo-frame appframe) appframe))
    (plain-error "ミニバッファ表示中はできません")))

(defun unique-pseudo-frame-name ()
  (let ((i *pseudo-frame-counter*))
    (loop
      (let ((hit nil)
	    (name (format nil "Frame ~D" i)))
	(dolist (appframe (frame-list))
	  (if (find-pseudo-frame name appframe) (setq hit t)))
	(or hit
	    (return (values name i))))
      (incf i))))

(defun make-pseudo-frame-name ()
  (multiple-value-bind (def counter)
      (unique-pseudo-frame-name)
    (let ((name (if *prefix-args*
		    (read-string "New frame: " :default def)
		  "")))
      (when (or (string= name "")
		(string= name def))
	(setq name def)
	(setq *pseudo-frame-counter* (+ counter 1)))
      name)))


(defun create-pseudo-frame-1 (appframe name &optional save-p selected-fn deleted-fn)
  (let ((frame (pseudo-frame-constructor name nil save-p selected-fn deleted-fn)))
    (set-pseudo-frame-list appframe (nconc (get-pseudo-frame-list appframe) (list frame)))
    (when (tool-bar-exist-p 'pseudo-frame-bar appframe)
      (tab-bar-add-item 'pseudo-frame-bar frame name nil nil appframe))
    frame))

(defun create-pseudo-frame (appframe name &optional save-p selected-fn deleted-fn)
  (pseudo-frame-check-minibuffer appframe)
  (when (find-pseudo-frame name appframe)
    (error "~Aはすでに存在します" name))
  (save-current-pseudo-frame appframe)
  (delete-other-windows appframe)
  (let ((frame (create-pseudo-frame-1 appframe name save-p selected-fn deleted-fn)))
    (set-current-pseudo-frame appframe frame)
    (when (tool-bar-exist-p 'pseudo-frame-bar appframe)
      (tab-bar-select-item 'pseudo-frame-bar frame appframe))
    (run-hooks '*select-pseudo-frame-hook*)
    frame))

(defun new-pseudo-frame-internal (appframe name save-p selected-fn deleted-fn)
  (pseudo-frame-check-minibuffer appframe)
  (create-pseudo-frame appframe name save-p selected-fn deleted-fn))

(defun new-pseudo-frame (name &optional save-p selected-fn deleted-fn)
  (interactive (list (progn
		       (pseudo-frame-check-minibuffer (selected-frame))
		       (make-pseudo-frame-name))
		     't))
  (new-pseudo-frame-internal (selected-frame) name save-p selected-fn deleted-fn))

(defun select-pseudo-frame (frame &optional (appframe (selected-frame)))
  (unless (eq frame (get-current-pseudo-frame appframe))
    (pseudo-frame-check-minibuffer appframe)
    (save-current-pseudo-frame appframe)
    (set-window-configuration (pseudo-frame-winconf frame) appframe)
    (set-current-pseudo-frame appframe frame)
    (when (tool-bar-exist-p 'pseudo-frame-bar appframe)
      (tab-bar-select-item 'pseudo-frame-bar frame appframe))
    (and (pseudo-frame-selected-fn frame)
	 (funcall (pseudo-frame-selected-fn frame appframe)))
    (run-hooks '*select-pseudo-frame-hook*)))

(defun switch-pseudo-frame (name)
  (interactive (list (completing-read "Frame: "
				      (mapcar #'pseudo-frame-name (get-pseudo-frame-list (selected-frame)))
				      :must-match t)))
  (select-pseudo-frame (or (find-pseudo-frame name (selected-frame))
			   (error "~aはフレームではありません" name)) (selected-frame)))

(defun pseudo-frame-selector ()
  (interactive)
  (multiple-value-bind (result data)
      (let ((l (sort (mapcar #'pseudo-frame-name (get-pseudo-frame-list (selected-frame))) #'string<)))
	(dialog-box '(dialog 0 0 153 115
		      (:caption "フレーム選択")
		      (:font 9 "MS UI Gothic")
		      (:control
		       (:listbox list nil #x50a10101 7 7 85 101)
		       (:button IDOK "OK" #x50010001 96 7 50 14)
		       (:button IDCANCEL "キャンセル" #x50010000 96 24 50 14)))
		    `((list . ,l)
		      (list . ,(position (pseudo-frame-name (selected-pseudo-frame)) l :test #'string=)))
		    nil))
    (when result
      (switch-pseudo-frame (cdr (assoc 'list data))))))

(defun other-pseudo-frame ()
  (interactive)
  (let* ((appframe (selected-frame))
	(frame (or (cadr (member (pseudo-frame-name (get-current-pseudo-frame appframe))
				 (get-pseudo-frame-list appframe)
				 :key #'pseudo-frame-name :test #'string=))
		   (car (get-pseudo-frame-list appframe)))))
    (unless (eq frame (get-current-pseudo-frame appframe))
      (select-pseudo-frame frame appframe)
      t)))

(setf (symbol-function 'next-pseudo-frame) #'other-pseudo-frame)

(defun previous-pseudo-frame ()
  (interactive)
  (let* ((appframe (selected-frame))
	(frame (let ((n (position (pseudo-frame-name (get-current-pseudo-frame appframe))
				  (get-pseudo-frame-list appframe)
				  :key #'pseudo-frame-name :test #'string=)))
		 (if (and n (plusp n))
		     (nth (- n 1) (get-pseudo-frame-list appframe))
		   (car (last (get-pseudo-frame-list appframe)))))))
    (unless (eq frame (get-current-pseudo-frame appframe))
      (select-pseudo-frame frame appframe)
      t)))

(defun delete-pseudo-frame (&optional (frame (get-current-pseudo-frame (selected-frame))))
  (interactive)
  (pseudo-frame-check-minibuffer (selected-frame))
  (and (pseudo-frame-deleted-fn frame)
       (funcall (pseudo-frame-deleted-fn frame)))
  (dolist (appframe (frame-list))
    (when (eq frame (get-current-pseudo-frame appframe))
      (other-pseudo-frame))
    (when (tool-bar-exist-p 'pseudo-frame-bar appframe)
      (tab-bar-delete-item 'pseudo-frame-bar frame appframe))
    (set-pseudo-frame-list appframe (delete (pseudo-frame-name frame) (get-pseudo-frame-list appframe)
					    :key #'pseudo-frame-name :test #'string=))
    (unless (get-pseudo-frame-list appframe)
      (init-pseudo-frame appframe)))
  t)


(defun rename-pseudo-frame (name)
  (interactive "sRename frame: ")
  (unless (zerop (length name))
    (progn
      (when (find-pseudo-frame name)
	(error "~Aはすでに存在します" name))
      ;; all the appframe must contain the same list of pseudoframe in the pseudo-frame-bar
      (let ((curapp (selected-frame))
	    (fail nil))
	(dolit (appframe (frame-list))
	       (unless (and (tool-bar-exist-p 'pseudo-frame-bar appframe)
			  (tab-bar-modify-item 'pseudo-frame-bar frame name nil nil appframe))
		 (setq fail t)))
	(unless fail
	  (setf (pseudo-frame-name frame) name))))))

(defun delete-all-pseudo-frames (&optional (create-new t))
  (dolist (appframe (frame-list))
    (let ((tb (tool-bar-exist-p 'pseudo-frame-bar appframe)))
      (mapc #'(lambda (frame)
		(and tb (tab-bar-delete-item 'pseudo-frame-bar frame appframe)))
	    (get-pseudo-frame-list appframe))
      (mapc #'(lambda (frame)
		(and (pseudo-frame-deleted-fn frame)
		     (funcall (pseudo-frame-deleted-fn frame))))
	    (get-pseudo-frame-list appframe))
      (set-pseudo-frame-list appframe nil)
      (when create-new
	(init-pseudo-frame appframe))))
  t)

(defun pseudo-frame-bar ()
  (let ((appframe (selected-frame)))
    (create-tab-bar 'pseudo-frame-bar #'(lambda (frame)
						   (select-pseudo-frame frame (selected-frame))
						   (refresh-screen 'foo)) appframe)
    (mapc #'(lambda (frame)
	      (tab-bar-add-item 'pseudo-frame-bar frame (pseudo-frame-name frame) nil nil appframe))
	  (get-pseudo-frame-list appframe))
    (tab-bar-select-item 'pseudo-frame-bar (get-current-pseudo-frame appframe) appframe)))

(defun init-pseudo-frame (&optional (appframe (selected-frame)))
  (unless (get-pseudo-frame-list appframe)
    (set-current-pseudo-frame appframe nil)
    (new-pseudo-frame-internal appframe (let ((*prefix-args* nil))
			(make-pseudo-frame-name))
		      't nil nil)))

(defun new-pseudo-frame-menu-update ()
  (if (window-buffer (minibuffer-window))
      :disable))

(defun pseudo-frame-menu-update ()
  (if (or (null (cdr (get-pseudo-frame-list (selected-frame))))
	  (window-buffer (minibuffer-window)))
      :disable))

(defun buffer-in-any-pseudo-frame-p (buffer)
  (member-if #'(lambda (frame)
		 (unless (eq frame (get-current-pseudo-frame (selected-frame)))
		   (member-if #'(lambda (x)
				  (member buffer x :test #'eq))
			      (caddr (pseudo-frame-winconf frame)))))
	     (get-pseudo-frame-list (selected-frame))))

(define-command-bar 'pseudo-frame-bar "フレーム(&F)")

(defvar ctl-x-6-map (make-sparse-keymap))
(setf (symbol-function 'ctl-x-6-prefix) ctl-x-6-map)

(global-set-key '(#\C-x #\6) 'ctl-x-6-prefix)
(define-key ctl-x-6-map #\0 'delete-pseudo-frame)
(define-key ctl-x-6-map #\2 'new-pseudo-frame)
(define-key ctl-x-6-map #\o 'other-pseudo-frame)
(define-key ctl-x-6-map #\p 'previous-pseudo-frame)
