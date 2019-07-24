;; Project-wide indentation settings for Emacs: use tabs, 8-chars wide, and fill at 92
;; columns. The indentation offset for Shell and C modes is one tab.
((nil . ((indent-tabs-mode . t)
         (tab-width . 8)
         (fill-column . 92)))
 (c-mode . ((c-basic-offset . 8)))
 (sh-mode . ((sh-basic-offset . 8))))
