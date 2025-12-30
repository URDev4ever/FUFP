<?php
// Simulate slow response
for($i = 0; $i < 5; $i++) {
  echo str_repeat("A", 102400); // 100KB chunks
  flush();
  sleep(2);
}
?>