(load #p"../sha.lisp")

(defpackage sha-test (:use common-lisp sha))
(in-package sha-test)

(defun read-lines (input)
  (do (list x) (nil)
    (setq x (read-line input nil nil))
    (unless x
      (return (nreverse list)))
    (push x list)))

(defun sha-string (x)
  (with-output-to-string (s)
    (dotimes (i (length x))
      (format s "~2,'0X" (aref x i)))))


;;
;;  sha256encode
;;
(defun sha256encode-equal (sha x y)
  (dotimes (i (length x))
    (byte-sha256encode sha (char-code (char x i))))
  (let* ((a (calc-sha256encode sha))
         (b (sha-string a)))
    (unless (equalp b y)
      (format t "ERROR: ~A, ~A, ~A~%" x y b)))
  (init-sha256encode sha))

(defun main-sha256encode ()
  (let ((sha (make-sha256encode))
        (file #p"hash.sha256"))
    (format t "Test: ~A~%" file)
    (with-open-file (input file)
      (dolist (str (read-lines input))
        (let* ((p (position #\Space str))
               (x (subseq str 0 p))
               (y (subseq str (1+ p))))
          (sha256encode-equal sha x y))))))


;;
;;  sha512encode
;;
(defun sha512encode-equal (sha x y)
  (dotimes (i (length x))
    (byte-sha512encode sha (char-code (char x i))))
  (let* ((a (calc-sha512encode sha))
         (b (sha-string a)))
    (unless (equalp b y)
      (format t "ERROR: ~A, ~A, ~A~%" x y b)))
  (init-sha512encode sha))

(defun main-sha512encode ()
  (let ((sha (make-sha512encode))
        (file #p"hash.sha512"))
    (format t "Test: ~A~%" file)
    (with-open-file (input file)
      (dolist (str (read-lines input))
        (let* ((p (position #\Space str))
               (x (subseq str 0 p))
               (y (subseq str (1+ p))))
          (sha512encode-equal sha x y))))))


;;
;;  sha384encode
;;
(defun sha384encode-equal (sha x y)
  (dotimes (i (length x))
    (byte-sha384encode sha (char-code (char x i))))
  (let* ((a (calc-sha384encode sha))
         (b (sha-string a)))
    (unless (equalp b y)
      (format t "ERROR: ~A, ~A, ~A~%" x y b)))
  (init-sha384encode sha))

(defun main-sha384encode ()
  (let ((sha (make-sha384encode))
        (file #p"hash.sha384"))
    (format t "Test: ~A~%" file)
    (with-open-file (input file)
      (dolist (str (read-lines input))
        (let* ((p (position #\Space str))
               (x (subseq str 0 p))
               (y (subseq str (1+ p))))
          (sha384encode-equal sha x y))))))


;;
;;  sha3encode
;;
(defun sha3encode-equal (sha size x y)
  (dotimes (i (length x))
    (byte-sha3encode sha (char-code (char x i))))
  (let* ((a (if size
              (result-sha3encode sha size)
              (calc-sha3encode sha)))
         (b (sha-string a)))
    (unless (equalp b y)
      (format t "ERROR: ~A, ~A, ~A~%" x y b)))
  (init-sha3encode sha))

(defun sha3encode-test (sha size file)
  (format t "Test: ~A~%" file)
  (with-open-file (input file)
    (dolist (str (read-lines input))
      (let* ((p (position #\Space str))
             (x (subseq str 0 p))
             (y (subseq str (1+ p))))
        (sha3encode-equal sha size x y)))))

(defun main-sha3encode ()
  (let ((sha (make-sha3-256-encode)))
    (sha3encode-test sha nil #p"hash.sha3-256"))
  (let ((sha (make-sha3-512-encode)))
    (sha3encode-test sha nil #p"hash.sha3-512"))
  (let ((sha (make-shake-256-encode)))
    (sha3encode-test sha nil #p"hash.shake-256-256"))
  (let ((sha (make-shake-256-encode)))
    (sha3encode-test sha 100 #p"hash.shake-256-800")))


;;
;;  test
;;
(main-sha256encode)
(main-sha512encode)
(main-sha384encode)
(main-sha3encode)

