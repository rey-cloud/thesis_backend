<?php
namespace App\Http\Controllers;

use App\Http\Requests\AuthenticateUserRequest;
use App\Http\Requests\AuthRequest;
use Illuminate\Http\Request;
use App\Http\Requests\LoginRequest; // Ensure correct import
use App\Http\Requests\UpdateUserRequest;
use App\Http\Resources\AuthenticatedUserResource;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Response;
use Illuminate\Validation\ValidationException as ValidationValidationException;

class AuthController extends Controller
{

    public function authenticateUser(AuthenticateUserRequest $payload)
    {
        $username = $payload->username; 
        $password = $payload->password;

        $user = User::where('username', $username)->first();

        if (!$user || !Hash::check($password, $user->password)) {
            throw ValidationValidationException::withMessages([
                'username' => ['Invalid login credentials.'],
            ]);
        }

        $response = (object) [
            'user' => $user,
            'token' => $user->createToken('auth-token')->plainTextToken
        ];

        return new AuthenticatedUserResource($response);
    }


    public function register(AuthRequest $request)
    {
        $user = User::create($request->validated());

        return response()->json([
            'user' => $user
        ]);
    }

    public function login(LoginRequest $request)
    {
        $user = User::where('username', $request->username)->first();

        // Check if the user exists and the password matches
        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json([
                'message' => 'The provided credentials are incorrect.'
            ], 401); // Return 401 Unauthorized
        }

        // Create a token for the authenticated user
        $token = $user->createToken($request->username)->plainTextToken;

        return response()->json([
            'user' => $user,
            'token' => $token
        ]);
    }

    public function logout(Request $request)
    {
        $request->user()->tokens()->delete();

        return response()->json([
            'message' => 'You are logged out.'
        ]);
    }

    public function getUser(Request $request) {
        return $request->user();;
    }

    public function loginAdmin(LoginRequest $request) {
        $user = User::where('username', $request->username)->first();
    
        // Check if the user exists and the password matches
        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json([
                'message' => 'The provided credentials are incorrect.'
            ], 401); // Return 401 Unauthorized
        }
    
        // Check if the user is an admin or superadmin
        if (!in_array($user->role, ['admin', 'superadmin'])) {
            return response()->json([
                'message' => 'Access denied. Admins only.'
            ], 403); // Return 403 Forbidden
        }
    
        // Create a token for the authenticated admin user
        $token = $user->createToken($request->username)->plainTextToken;
    
        return response()->json([
            'user' => $user,
            'token' => $token
        ]);
    }
    
    public function logoutUser(Request $request) {
        $user = $request->user();
        $user->tokens()->delete();
        return 'Success';
    }

    public function updateUser(UpdateUserRequest $request, $username)
    {
        // Find the user by username
        $user = User::where('username', $username)->first();

        if (!$user) {
            return response()->json(['message' => 'User not found.'], 404);
        }

        // Update the user with validated data from the request
        $user->update($request->validated());

        return response()->json([
            'user' => $user,
            'message' => 'User updated successfully.'
        ]);
    }


    public function getAllUsers() {
        $users = User::all(); // Fetch all users
        return response()->json($users);
    }

    public function getUserById($username)
    {
        // Find the user by username
        $user = User::where('username', $username)->first();

        if (!$user) {
            return response()->json(['message' => 'User not found'], 404);
        }

        return response()->json([
            'user' => $user,
            'message' => 'User retrieved successfully.'
        ]);
    }

    public function setStatus(Request $request, $id)
    {
        $user = User::find($id);

        if (!$user) {
            return response()->json(['message' => 'User not found.'], 404);
        }

        // Toggle the status
        $user->status = $user->status === 'active' ? 'inactive' : 'active';
        $user->save();

        return response()->json([
            'user' => $user,
            'message' => 'User status updated successfully.',
        ]);
    }


}
