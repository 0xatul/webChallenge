<?php

class Chicken{
    public function __destruct(){
        echo "things happened";
        file_put_contents($this->name, $this->content, FILE_APPEND);
    }
}

?>