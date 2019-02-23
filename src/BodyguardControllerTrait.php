<?php

    namespace BodyguardClient;

    use GuzzleHttp\Exception\GuzzleException;
    use Symfony\Component\HttpFoundation\JsonResponse;
    use Symfony\Component\HttpFoundation\Request;

    trait BodyguardControllerTrait
    {
        protected $applicationId;
        protected $applicationSecret;
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

        /**
         * @param Request $request
         *
         * @return JsonResponse
         * @throws GuzzleException
         */
        public function registerAction(Request $request): JsonResponse
        {
            $bodyguardClient = $this->getBodyguardClient($request);
            $data = $this->getPostData($request);

            try {
                $response = json_decode($bodyguardClient->registerUser(
                    $data['username'],
                    $data['email'],
                    $data['password']
                )->getBody()->getContents(), true);

                return new JsonResponse($response);
            } catch (BodyguardException $e) {
                return new JsonResponse([
                    'status' => $e->getCode(),
                    'message' => $e->getMessage()
                ]);
            }
        }

        /**
         * @param Request $request
         *
         * @return JsonResponse
         * @throws GuzzleException
         */
        public function loginAction(Request $request): JsonResponse
        {
            $bodyguardClient = $this->getBodyguardClient($request);
            $data = $this->getPostData($request);

            try {
                $response = json_decode($bodyguardClient->loginUser(
                    $data['email'],
                    $data['password']
                )->getBody()->getContents(), true);

                return new JsonResponse($response);
            } catch (BodyguardException $e) {
                return new JsonResponse([
                    'status' => $e->getCode(),
                    'message' => $e->getMessage()
                ]);
            }
        }

        /**
         * @param Request $request
         *
         * @return JsonResponse
         * @throws GuzzleException
         */
        public function tokenAction(Request $request): JsonResponse
        {
            $bodyguardClient = $this->getBodyguardClient($request);
            $data = $request->query->all();

            try {
                $response = json_decode($bodyguardClient->getUserSessionToken(
                    $data['user_id'],
                    $data['user_secret']
                )->getBody()->getContents(), true);

                return new JsonResponse($response);
            } catch (BodyguardException $e) {
                return new JsonResponse([
                    'status' => $e->getCode(),
                    'message' => $e->getMessage()
                ]);
            }
        }

        /**
         * @param Request $request
         *
         * @return JsonResponse
         * @throws GuzzleException
         */
        public function validateTokenAction(Request $request): JsonResponse
        {
            $bodyguardClient = $this->getBodyguardClient($request);

            try {
                $response = json_decode($bodyguardClient->validateToken(
                    $request->headers->get('authorization')
                )->getBody()->getContents(), true);

                return new JsonResponse($response);
            } catch (BodyguardException $e) {
                return new JsonResponse([
                    'status' => $e->getCode(),
                    'message' => $e->getMessage()
                ]);
            }
        }

        /**
         * @param Request $request
         *
         * @return JsonResponse
         * @throws GuzzleException
         */
        public function logoutAction(Request $request): JsonResponse
        {
            $bodyguardClient = $this->getBodyguardClient($request);

            try {
                $response = json_decode($bodyguardClient->logout(
                    $request->headers->get('authorization')
                )->getBody()->getContents(), true);

                return new JsonResponse($response);
            } catch (BodyguardException $e) {
                return new JsonResponse([
                    'status' => $e->getCode(),
                    'message' => $e->getMessage()
                ]);
            }
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
