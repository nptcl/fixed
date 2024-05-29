(defconstant +bit+ 128)

(defun rotatel (x w m)
  (setq m (mod m w))
  (mod (logior
         (ash x m)
         (ash x (- m w)))
       (ash 1 w)))

(defun rotater (x w m)
  (setq m (mod m w))
  (mod (logior
         (ash x (- m))
         (ash x (- w m)))
       (ash 1 w)))

(defun main-call (s call v bit x y)
  (dotimes (i (- y x))
    (format s "16 ~X ~X ~X~%" v (+ x i) (funcall call v bit (+ x i)))))

(defun main (call list file)
  (with-open-file (s file :direction :output
                     :if-exists :supersede
                     :if-does-not-exist :create)
    (format s "~A~%" +bit+)
    (dolist (x list)
      (main-call s call x +bit+ 0 10)
      (main-call s call x +bit+ 60 70)
      (main-call s call x +bit+ 120 130)
      (main-call s call x +bit+ 250 260))))

(let ((*random-state* (make-random-state t)))
  (let ((x (list 1
                 (random (ash 1 +bit+))
                 (random (ash 1 +bit+))
                 (random (ash 1 +bit+))
                 (random (ash 1 +bit+))
                 (random (ash 1 +bit+)))))
    (main #'rotatel x #p"rotatel.txt")
    (main #'rotater x #p"rotater.txt")))


