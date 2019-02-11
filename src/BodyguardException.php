<?php

    namespace BodyguardClient;

    class BodyguardException extends \Exception
    {
        private $title;

        public function __construct(int $code, string $title, string $message)
        {
            parent::__construct($message, $code);

            $this->title = $title;
        }

        public function getTitle()
        {
            $this->getTitle();
        }
    }
