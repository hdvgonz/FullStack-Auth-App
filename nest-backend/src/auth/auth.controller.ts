/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable prettier/prettier */
import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseGuards,
  Request,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { UpdateAuthDto, CreateUserDto, LoginDto, RegisterUserDto } from './dto';
import { AuthGuard } from './guards/auth.guard';
import { User } from './entities/user.entity';
import { LoginResponse } from './interfaces/login.response';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post()
  create(@Body() createUserDto: CreateUserDto) {
    return this.authService.create(createUserDto);
  }

  @UseGuards(AuthGuard)
  @Get()
  findAll(@Request() req: Request) {
    //Dentro del request hay una propiedad que se llama user, es donde metimos el id del payload en el AuthGuard
    // const user = req['user'];
    // return user;
    return this.authService.findAll();
  }

  // @Get(':id')
  // findOne(@Param('id') id: string) {
  //   return this.authService.findOne(+id);
  // }

  // @Patch(':id')
  // update(@Param('id') id: string, @Body() updateAuthDto: UpdateAuthDto) {
  //   return this.authService.update(+id, updateAuthDto);
  // }

  // @Delete(':id')
  // remove(@Param('id') id: string) {
  //   return this.authService.remove(+id);
  // }

  @Post('login')
  login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }

  @Post('register')
  register(@Body() registerDto: RegisterUserDto) {
    return this.authService.register(registerDto);
  }

  /**
   * 1. Asegurarnos de que la persona sea quien dice que es.
   * 2. Prolongar la vida del token, generando uno nuevo
   * @param req 
   * @returns 
   */
  @UseGuards(AuthGuard)
  @Get('check-token')
  checkToken(@Request() req: Request): LoginResponse {
    const user = req['user'] as User;

    return {
      user,
      token: this.authService.getJwToken({ id: user._id }),
    };
  }
}
