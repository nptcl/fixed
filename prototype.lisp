(defun power-mod (x y n &optional (r 1))
  (if (< 0 y)
    (power-mod
      (mod (* x x) n)
      (ash y -1)
      n
      (if (logbitp 0 y)
        (mod (* r x) n)
        r))
    r))


;;
;;  prime
;;
(defun prime-times (bit)
  (cond ((>= bit 1300) 2)
        ((>= bit 850) 3)
        ((>= bit 650) 4)
        ((>= bit 550) 5)
        ((>= bit 450) 6)
        ((>= bit 400) 7)
        ((>= bit 350) 8)
        ((>= bit 300) 9)
        ((>= bit 250) 12)
        ((>= bit 200) 15)
        ((>= bit 150) 18)
        (t 27)))

(defun prime-loop-p (x k)
  (let* ((n1 (1- x))
         (n2 n1))
    (do () ((logbitp 0 n2))
      (setq n2 (ash n2 -1)))
    (dotimes (ignore k t)
      (let* ((a (1+ (random (- x 2))))
             (b n2)
             (c (power-mod a b x)))
        (do () ((or (= c 1) (= b n1) (= c n1)))
          (setq c (mod (* c c) x))
          (setq b (ash b 1)))
        (and (/= c n1)
             (not (logbitp 0 b))
             (return nil))))))

(defun prime-p (x bit)
  (cond ((= x 2) t)
        ((= x 1) nil)
        ((not (logbitp 0 x)) nil)
        (t (let ((k (prime-times bit)))
             (prime-loop-p x k)))))

(defun prime-random (bit)
  (logior 1
          (ash 1 (1- bit))
          (random (ash 1 bit))))

(defun make-prime (bit &optional output)
  (prog (r (i 0))
    loop
    (when output
      (format output ".")
      (finish-output output))
    (setq r (prime-random bit))
    (unless (prime-p r bit)
      (incf i 1)
      (go loop))
    (when output
      (format output "~%make-prime: ~A~%" i)
      (finish-output output))
    (return r)))


;;
;;  rsa
;;
(defun rsa-extended-euclidean (x y &optional (x0 1) (x1 0) (y0 0) (y1 1))
  (if (zerop y)
    (values x0 y0 x)
    (multiple-value-bind (q z) (truncate x y)
      (let ((x2 (- x0 (* q x1)))
            (y2 (- y0 (* q y1))))
        (rsa-extended-euclidean y z x1 x2 y1 y2)))))

(defun rsa-number-d (e pq1)
  (mod (rsa-extended-euclidean e pq1) pq1))

(defun make-rsakey (bit)
  (let* ((half (ash bit -1))
         (p (make-prime half))
         (q (make-prime half))
         (e 65537)
         (n (* p q))
         (pq1 (* (1- p) (1- q)))
         (d (rsa-number-d e pq1)))
    (values e d n p q)))


;;
;;  main
;;
(defun rsa-translate (list y n)
  (mapcar
    (lambda (x) (power-mod x y n))
    list))

(defun main-rsa (bit)
  (let ((*random-state* (make-random-state t)))
    (multiple-value-bind (e d n) (make-rsakey bit)
      (format t "~S~%" (list 'public e n))
      (format t "~S~%" (list 'private d n))
      (let* ((list '(10 20 30 40 50))
             (x1 (rsa-translate list e n))
             (y1 (rsa-translate x1 d n))
             (x2 (rsa-translate list d n))
             (y2 (rsa-translate x2 e n)))
        (format t "~S~%" list)
        (format t "~S~%" x1)
        (format t "~S~%" y1)
        (format t "~S~%" x2)
        (format t "~S~%" y2)))))

(main-rsa 256)

