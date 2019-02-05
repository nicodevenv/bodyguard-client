<?php

    namespace BodyguardClient;

    use GuzzleHttp\Client;
    use GuzzleHttp\Exception\GuzzleException;

    class BodyguardClient
    {
        public const CLIENT_ID_INDEX = 'client_id';

        public const CLIENT_SECRET_INDEX = 'client_secret';

        public const AUTHORIZATION = 'Authorization';

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
         */
        public function registerUser(string $username, string $email, string $password): array
        {
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
         */
        public function loginUser(string $usernameOrEmail, string $password): array
        {
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
         */
        public function getUserSessionToken(string $userSpecialLogin, string $userSpecialSecret): array
        {
            return $this->postToBodyguard(
                '/api/oauth/token',
                [
                    'user_id'     => $userSpecialLogin,
                    'user_secret' => $userSpecialSecret,
                ]
            );
        }

        /**
         * @param string $authorization
         *
         * @return array
         */
        public function validateToken(string $authorization): array
        {
            return $this->getFromBodyguard('/api/oauth/token', $authorization);
        }

        /**
         * @return bool
         */
        public function getIsInternal(): bool
        {
            return $this->isInternal;
        }

        /**
         * @param string      $url
         * @param array       $postData
         * @param null|string $authorization
         *
         * @return array
         */
        private function postToBodyguard(string $url, array $postData, ?string $authorization = null): array
        {
            try {
                return $this->client->request('POST', $this->baseUrl . $url, [
                    'headers'     => $this->getHeaders($authorization),
                    'form_params' => $postData,
                ]);
            } catch (GuzzleException $e) {
                return $this->getGuzzleError($e);
            }
        }

        /**
         * @param string $url
         * @param string $authorization
         *
         * @return array
         */
        private function getFromBodyguard(string $url, string $authorization): array
        {
            try {
                return $this->client->request('GET', $this->baseUrl . $url, [
                    'headers' => $this->getHeaders($authorization),
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
         */
        private function getHeaders(?string $authorization): array
        {
            $headers = [
                'Accept'     => 'application/json',
                'ip'         => $this->ip,
                'User-Agent' => $this->userAgent,
            ];

            if (null === $authorization) {
                $this->isInternal         = false;
                $headers['Authorization'] = $authorization;

                return $headers;
            }

            $this->isInternal         = true;
            $headers['client_id']     = $this->applicationId;
            $headers['client_secret'] = $this->applicationSecret;

            return $headers;
        }
    }
