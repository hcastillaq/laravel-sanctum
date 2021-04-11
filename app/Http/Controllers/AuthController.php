<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{

    public function __construct()
    {
        $this->middleware('auth:sanctum')->only('logout');    
    }

    public function register(Request $request){
        $fields = $request->validate([
            'email'=>'required|unique:users',
            'password'=>'required|string',
            'name'=>'required|string'
        ]);

        $user = new User($fields);
        $user->password = bcrypt($user->password);
        $user->save();

        return response()->json([
            'user' => $user,
            'token' => $user->createToken('appToken')->plainTextToken
        ], 200);
    }

    public function login(Request $request){
        $fields = $request->validate([
            'email'=>'required|exists:users',
            'password' => 'required'
        ]);

        $user = User::where('email', $fields['email'])->first();

        if(!Hash::check($fields['password'], $user->password)){
            return response()->json([
                'msg'=> 'Bad Credentials'
            ], 401);
        }

        return response()->json([
            'user' => $user,
            'token' => $user->createToken('appToken')->plainTextToken
        ], 200);
    }

    public function logout(Request $request){
        $request->user()->currentAccessToken()->delete();
        return response()->json(['msg' => 'logout'], 200);
    }
}
