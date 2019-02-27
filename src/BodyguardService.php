<?php

    namespace BodyguardClient;

    use GuzzleHttp\Exception\GuzzleException;
    use Symfony\Component\HttpFoundation\Request;

    class BodyguardService
    {
        /** @var string */
        protected $applicationId;

        /** @var string */
        protected $applicationSecret;

        /** @var string */
        protected $baseUrl;

        public function __construct(
            string $applicationId,
            string $applicationSecret,
            string $bodyguardBaseUrl
        ) {
            $this->baseUrl = $bodyguardBaseUrl;
            $this->applicationId = $applicationId;
            $this->applicationSecret = $applicationSecret;
        }

        public function register(Request $request, array $data): array
        {
            $bodyguardClient = $this->getBodyguardClient($request);

            try {
                return json_decode($bodyguardClient->registerUser(
                    $data['username'],
                    $data['email'],
                    $data['password']
                )->getBody()->getContents(), true);
            } catch (BodyguardException $e) {
                return $this->getBodyguardException($e);
            } catch (GuzzleException $e) {
                return $this->getBodyguardException($e);
            }
        }

        public function login(Request $request, array $data): array
        {
            $bodyguardClient = $this->getBodyguardClient($request);

            try {
                return json_decode($bodyguardClient->loginUser(
                    $data['email'],
                    $data['password']
                )->getBody()->getContents(), true);
            } catch (BodyguardException $e) {
                return $this->getBodyguardException($e);
            } catch (GuzzleException $e) {
                return $this->getBodyguardException($e);
            }
        }

        public function getToken(Request $request, array $data): array
        {
            $bodyguardClient = $this->getBodyguardClient($request);

            try {
                return json_decode($bodyguardClient->getUserSessionToken(
                    $data['user_id'],
                    $data['user_secret']
                )->getBody()->getContents(), true);
            } catch (BodyguardException $e) {
                return $this->getBodyguardException($e);
            } catch (GuzzleException $e) {
                return $this->getBodyguardException($e);
            }
        }

        public function validateToken(Request $request): array
        {
            $bodyguardClient = $this->getBodyguardClient($request);

            try {
                return json_decode($bodyguardClient->validateToken(
                    $request->headers->get('authorization')
                )->getBody()->getContents(), true);
            } catch (BodyguardException $e) {
                return $this->getBodyguardException($e);
            } catch (GuzzleException $e) {
                return $this->getBodyguardException($e);
            }
        }

        public function logout(Request $request): array
        {
            $bodyguardClient = $this->getBodyguardClient($request);

            try {
                return json_decode($bodyguardClient->logout(
                    $request->headers->get('authorization')
                )->getBody()->getContents(), true);
            } catch (BodyguardException $e) {
                return $this->getBodyguardException($e);
            } catch (GuzzleException $e) {
                return $this->getBodyguardException($e);
            }
        }

        /**
         * @param BodyguardException|GuzzleException $exception
         *
         * @return array
         */
        public function getBodyguardException($exception): array
        {
            return [
                'status' => $exception->getCode(),
                'message' => $exception->getMessage()
            ];
        }

        /**
         * @param Request $request
         * @param bool    $strict
         *
         * @return null|string
         * @throws BodyguardException
         */
        public function getUserId(Request $request, bool $strict): ?string
        {
            $tokenValidation = null;

            if ($request->headers->get('authorization')) {
                $tokenValidation = $this->validateToken($request);

                if ($strict && !isset($tokenValidation['data']['user_data']['user_id'])) {
                    throw new BodyguardException('403', 'Invalid token', 'User id not found in token validation request');
                }
            }

            if (null !== $tokenValidation){
                return $tokenValidation['data']['user_data']['user_id'];
            }

            return null;
        }

        private function getBodyguardClient(Request $request): BodyguardClient
        {
            return new BodyguardClient(
                $this->baseUrl,
                $this->applicationId,
                $this->applicationSecret,
                $request->getClientIp(),
                $request->headers->get('user-agent')
            );
        }
    }
