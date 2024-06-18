#!/usr/bin/env -S sbcl --script

(defun make-hashkey (n)
  (dotimes (i n)
    (write-char
      (code-char (case (random 3)
                   (0 (+ (random 26) (char-code #\A)))
                   (1 (+ (random 26) (char-code #\a)))
                   (2 (+ (random 10) (char-code #\0))))))))

(let ((*random-state* (make-random-state t)))
  (dotimes (n 1024)
    (unless (zerop n)
      (make-hashkey n)
      (fresh-line))))

