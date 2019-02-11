<?php

    namespace BodyguardClient;

    use GuzzleHttp\Client;
    use GuzzleHttp\Exception\GuzzleException;

    class BodyguardClient
    {
        public const MODE_APPLICATION = 'application';
        public const MODE_SESSION = 'session';
        public const MODE_TOKEN = 'token';

        /** @var string */
        private $baseUrl;

        /** @var string */
        private $applicationId;

        /** @var string */
        private $applicationSecret;

        /** @var Client */
        private $client;

        /** @var bool */
        private $isInternal;

        /** @var string */
        private $ip;

        /** @var string */
        private $userAgent;

        /** @var string */
        private $currentMode;

        /**
         * BodyguardClient constructor.
         *
         * @param string $baseUrl
         * @param string $applicationId
         * @param string $applicationSecret
         * @param string $ip
         * @param string $userAgent
         */
        public function __construct(string $baseUrl, string $applicationId, string $applicationSecret, string $ip, string $userAgent)
        {
            $this->baseUrl           = $baseUrl;
            $this->applicationId     = $applicationId;
            $this->applicationSecret = $applicationSecret;
            $this->ip                = $ip;
            $this->userAgent         = $userAgent;

            $this->client = new Client();
        }

        /**
         * @param string $username
         * @param string $email
         * @param string $password
         *
         * @return array
         * @throws BodyguardException
         */
        public function registerUser(string $username, string $email, string $password): array
        {
            $this->setMode(self::MODE_APPLICATION);

            return $this->postToBodyguard(
                '/api/user/register',
                [
                    'username' => $username,
                    'email'    => $email,
                    'password' => $password,
                ]
            );
        }

        /**
         * @param string $usernameOrEmail
         * @param string $password
         *
         * @return array
         * @throws BodyguardException
         */
        public function loginUser(string $usernameOrEmail, string $password): array
        {
            $this->setMode(self::MODE_APPLICATION);

            return $this->postToBodyguard(
                '/api/user/login',
                [
                    'email'    => $usernameOrEmail,
                    'password' => $password,
                ]
            );
        }

        /**
         * @param string $userSpecialLogin
         * @param string $userSpecialSecret
         *
         * @return array
         * @throws BodyguardException
         */
        public function getUserSessionToken(string $userSpecialLogin, string $userSpecialSecret): array
        {
            $this->setMode(self::MODE_SESSION);

            return $this->getFromBodyguard('/api/oauth/token', $userSpecialLogin, $userSpecialSecret);
        }

        /**
         * @param string $authorization
         *
         * @return array
         * @throws BodyguardException
         */
        public function validateToken(string $authorization): array
        {
            $this->setMode(self::MODE_TOKEN);

            return $this->getFromBodyguard('/api/oauth/token', $authorization);
        }

        /**
         * @param string $authorization
         *
         * @return array
         * @throws BodyguardException
         */
        public function logout(string $authorization): array
        {
            $this->setMode(self::MODE_TOKEN);

            return $this->getFromBodyguard('/api/oauth/logout', $authorization);
        }

        /**
         * @param string      $url
         * @param array       $postData
         * @param null|string $arg1
         * @param null|string $arg2
         *
         * @return array
         * @throws BodyguardException
         */
        private function postToBodyguard(string $url, array $postData, ?string $arg1 = null, ?string $arg2 = null): array
        {
            try {
                return $this->client->request('POST', $this->getUrl($url, $arg1, $arg2), [
                    'headers'     => $this->getHeaders($arg1),
                    'form_params' => $postData,
                ]);
            } catch (GuzzleException $e) {
                return $this->getGuzzleError($e);
            }
        }

        /**
         * @param string      $url
         * @param null|string $arg1
         * @param null|string $arg2
         *
         * @return array
         * @throws BodyguardException
         */
        private function getFromBodyguard(string $url, ?string $arg1 = null, ?string $arg2 = null): array
        {
            try {
                return $this->client->request('GET', $this->getUrl($url, $arg1, $arg2), [
                    'headers' => $this->getHeaders($arg1),
                ]);
            } catch (GuzzleException $e) {
                return $this->getGuzzleError($e);
            }
        }

        /**
         * @param GuzzleException $e
         *
         * @return array
         */
        private function getGuzzleError(GuzzleException $e)
        {
            return [
                'status'  => $e->getCode(),
                'message' => $e->getMessage(),
            ];
        }

        /**
         * @param null|string $authorization
         *
         * @return array
         * @throws BodyguardException
         */
        private function getHeaders(?string $authorization): array
        {
            $headers = [
                'Accept'     => 'application/json',
            ];

            if ($this->currentMode === self::MODE_TOKEN) {
                if ($authorization === null) {
                    throw new BodyguardException(
                        400,
                        'Invalid token',
                        'Please provide a token'
                    );
                }
                $headers['Authorization'] = $authorization;
            }

            return $headers;
        }

        /**
         * @param string      $url
         * @param null|string $arg1
         * @param null|string $arg2
         *
         * @return string
         */
        private function getUrl(string $url, ?string $arg1, ?string $arg2): string
        {
            switch ($this->currentMode) {
                case self::MODE_APPLICATION:
                    $url .= sprintf('?client_id=%s&client_secret=%s&', $this->applicationId, $this->applicationSecret);
                    break;
                case self::MODE_SESSION:
                    $url .= sprintf('?user_id=%s&user_secret=%s&', $arg1, $arg2);
                    break;
                default:
                    $url .= '?';
            }

            $url .= sprintf('ip=%s&userAgent=%s', $this->ip, $this->userAgent);

            return $this->baseUrl . $url;
        }

        /**
         * @param string $mode
         *
         * @throws BodyguardException
         */
        private function setMode(string $mode)
        {
            if (!in_array($mode, [
                self::MODE_APPLICATION,
                self::MODE_SESSION,
                self::MODE_TOKEN,
            ])) {
                throw new BodyguardException(400, 'Wrong mode', 'Provided mode is not allowed : ' . $mode);
            }

            $this->currentMode = $mode;
        }
    }
