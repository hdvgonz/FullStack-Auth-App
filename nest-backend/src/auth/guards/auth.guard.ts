/* eslint-disable prettier/prettier */
/* eslint-disable @typescript-eslint/no-unused-vars */
import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from '../interfaces/jwt.payload';
import { AuthService } from '../auth.service';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private jwtService: JwtService,
    private authService: AuthService,
    
    ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    //Tomando request de la peiticion(url, etc)
    const request = context.switchToHttp().getRequest();

    const token = this.extractTokenFromHeader(request);

    if (!token) {
      throw new UnauthorizedException('Bearer Token is missing');
    }

    try {
      const payload = await this.jwtService.verifyAsync<JwtPayload>(token, {
        secret: process.env.JWT_SEED,
      });

      const user = await this.authService.findUserById( payload.id);

      if ( !user ) {
        throw new UnauthorizedException('User does not exist');
      }
      if ( !user.isActive ) {
        throw new UnauthorizedException('User is not active');
      }
      //Assigning the payload to the request object here
      //So we can access it in our  route handlers
      // request['user'] = payload.id;
      request['user'] = user;
    } catch {
      throw new UnauthorizedException();
    }
    return true;
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers['authorization']?.split(' ') ?? [];

    return type === 'Bearer' ? token : undefined;
  }
}
