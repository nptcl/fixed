(defconstant +bit+ 128)

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

(defun main1 (x y z)
  (let ((x1 (ash 1 x))
        (y1 (ash 1 y))
        (z1 (ash 1 z)))
    (dotimes (loop1 3)
      (dotimes (loop2 3)
        (let ((x2 (logior 1 (random x1)))
              (y2 (logior 1 (random y1)))
              (z2 (logior 1 (random z1))))
        (format t "16 ~X ~X ~X ~X~%"
                x2 y2 z2 (power-mod x2 y2 z2)))))))

(let ((*random-state* (make-random-state t)))
  (format t "~A~%" +bit+)
  (main1 10 5 5)
  (main1 5 10 5)
  (main1 128 40 10)
  (main1 40 128 40)
  (main1 128 128 128)
  (main1 128 128 128)
  )

