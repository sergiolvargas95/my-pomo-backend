<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Validator;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use \stdClass;

class AuthController extends Controller
{
    /**
     * The function `createUser` creates a new user in a PHP application, validates the input data, and
     * returns a JSON response with the user's information and a token.
     *
     * @param Request request The  parameter is an instance of the Request class, which
     * represents an HTTP request. It contains all the data and information about the incoming request,
     * such as the request method, headers, query parameters, form data, and more. In this case, it is
     * used to retrieve the input data sent
     *
     * @return a JSON response. If the validation fails, it returns a JSON response with status false
     * and an array of validation errors. If the validation passes and a new user is successfully
     * created, it returns a JSON response with status true, a success message, and a token for the
     * newly created user.
     */
    public function createUser(Request $request) {
        $rules = [
            'name' => 'required|string|max:100',
            'email' => 'required|string|email|max:100|unique:users',
            'password' => 'required|string|min:8'
        ];

        $validator = Validator::make($request->all(), $rules);

        if($validator->fails()) {
            return response()->json([
                'status' => false,
                'errors' => $validator->errors()
            ], 400);
        }

        //create a new user
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password)
        ]);

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'status' => true,
            'message' => 'User created successfully',
            'access_token' => $token,
            'token_type' => 'Bearer'
        ], 200);
    }

    /**
     * The above function is a PHP code snippet for handling user login, including validation,
     * authentication, and generating an API token.
     *
     * @param Request request The  parameter is an instance of the Request class, which
     * represents an HTTP request. It contains information about the request such as the request
     * method, headers, and input data.
     *
     * @return a JSON response. If the validation fails, it returns a response with status false and an
     * array of validation errors. If the authentication attempt fails, it returns a response with
     * status false and an array with the message "Unauthorized". If the authentication is successful,
     * it returns a response with status true, a success message, the user data, and a token for API
     * authentication.
     */
    public function login(Request $request) {
        $rules = [
            'email' => 'required|string|email|max:100',
            'password' => 'required|string'
        ];

        $validator = Validator::make($request->all(), $rules);
        if($validator->fails()) {
            return response()->json([
                'status' => false,
                'errors' => $validator->errors()
            ], 400);
        }

        if(!Auth::attempt($request->only('email', 'password'))) {
            return response()->json([
                'status' => false,
                'errors' => ['Unauthorized']
            ], 401);
        }

        $user = User::where('email', $request->email)->firstOrFail(['id','name','email']);

        $data = array(
            'id' => $user['id'],
            'name' => $user['name'],
            'email' => $user['email'],
            'isLogged' => true
        );

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'status' => true,
            'message' => 'User logged in successfully',
            'data' => $data,
            'token' => $token,
            'token_type' => 'Bearer'
        ], 200);
    }

    /**
     * The above function logs out the user by deleting all their tokens and returns a JSON response
     * indicating the success of the logout operation.
     *
     * @return a JSON response with a status of true and a message indicating that the user has been
     * logged out successfully.
     */
    public function logout() {
        Auth::user()->tokens()->delete();
        return response()->json([
            'status' => true,
            'message' => 'User logged out successfully'
        ]);
    }

    public function getprueba() {
        return response()->json('api');
    }
}
