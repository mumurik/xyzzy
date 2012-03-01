;;; -*- Mode: Lisp; Package: EDITOR -*-
;;;
;;; This file is part of xyzzy.
;;;

(provide "frame")

(in-package "editor")

(export '(delete-other-frames))

(defun delete-other-frames() 
  (interactive)
  (let ((cur (selected-frame)))
    (dolist (frame (frame-list))
      (unless (eq cur frame)
	(delete-frame frame)))))

(define-key ctl-x-5-map #\2 'make-frame)
(define-key ctl-x-5-map #\o 'other-frame)
(define-key ctl-x-5-map #\1 'delete-other-frames)
(define-key ctl-x-5-map #\0 'delete-frame)

