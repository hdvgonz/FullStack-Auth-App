/* eslint-disable prettier/prettier */
/* eslint-disable @typescript-eslint/no-unused-vars */
import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';

import {} from './dto/update-auth.dto';
import { InjectModel } from '@nestjs/mongoose';
import { JwtPayload } from './interfaces/jwt.payload';
import { JwtService } from '@nestjs/jwt';
import {
  LoginDto,
  RegisterUserDto,
  CreateUserDto,
  UpdateAuthDto,
} from './dto/';
import { LoginResponse } from './interfaces/login.response';
import { Model } from 'mongoose';
import { User } from './entities/user.entity';
import * as bcryptjs from 'bcryptjs';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name)
    private userModel: Model<User>,
    private jwtService: JwtService,
  ) {}
  async create(createUserDto: CreateUserDto) {
    //1 Encriptar pw,
    //2 Guardar user
    try {
      const { password, ...userData } = createUserDto;

      const newUser = new this.userModel({
        password: bcryptjs.hashSync(password, 10),
        ...userData,
      });
      await newUser.save();

      const { password: _, ...user } = newUser.toJSON();

      return user;
    } catch (error) {
      this.errorHandler(error.code);
    }
  }

  async login(loginDto: LoginDto): Promise<LoginResponse> {
    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email });

    if (!user) {
      throw new UnauthorizedException(`Not valid credentials - email`);
    }

    if (!bcryptjs.compare(password, user.password))
      throw new UnauthorizedException(`Not valid credentials - password`);

    const { password: _, ...userData } = user.toJSON();

    return {
      user: userData,
      token: this.getJwToken({ id: user.id }),
    };
  }

  async register(registerData: RegisterUserDto): Promise<LoginResponse> {
    const user = await this.create(registerData);
    console.log({ user });

    return {
      user: user,
      token: this.getJwToken({ id: user._id }),
    };
  }

  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById(id: string) {
    const user = await this.userModel.findById(id);
    const { password, ...restData } = user.toJSON(); //toJson para evitar que mande metodos y cosas propias del objecto

    return restData;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwToken(payload: JwtPayload) {
    const token = this.jwtService.sign(payload);

    return token;
  }

  private errorHandler(errorCode) {
    if (errorCode === 11000) {
      throw new BadRequestException(
        `Email already exists, please use a different one`,
      );
    }

    throw new InternalServerErrorException(
      `Something went bad on your request`,
    );
  }
}
