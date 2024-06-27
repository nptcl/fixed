(defpackage work (:use common-lisp elliptic))
(in-package work)

;;
;;  sign, verify
;;
(defun main-verify ()
  (let* ((private (make-private))
         (public (make-public private))
         (message1 (map 'vector #'char-code "Hello"))
         (message2 (map 'vector #'char-code "Hello")))
    (multiple-value-bind (r s) (sign private message1)
      (format t "Sign1: ~X~%" r)
      (format t "Sign2: ~X~%" s)
      (let ((x (verify public message2 r s)))
        (format t "Veriry: ~X~%" x)))))

(let ((*random-state* (make-random-state t)))
  (with-elliptic-secp256k1 (main-verify))
  (with-elliptic-secp256r1 (main-verify))
  (with-elliptic-ed25519 (main-verify))
  (with-elliptic-ed448 (main-verify)))

