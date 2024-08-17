import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from '../interfaces/jwt-payload';
import { AuthService } from '../auth.service';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private jwtService: JwtService, // Inyecta el servicio JWT para manejar la verificación del token
    private authService: AuthService, // Inyecta el servicio de autenticación para buscar al usuario en la base de datos
  ) {}

  // Método principal del Guard que determina si una solicitud puede proceder
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest(); // Obtiene el objeto de la solicitud HTTP
    const token = this.extractTokenFromHeader(request); // Extrae el token JWT del encabezado de autorización

    // Verifica si el token está presente; si no, lanza una excepción de autorización
    if (!token) {
      throw new UnauthorizedException('There is not a bearer token');
    }

    try {
      // Verifica y decodifica el token utilizando el servicio JWT, pasando la semilla secreta
      const payload = await this.jwtService.verifyAsync<JwtPayload>(token, {
        secret: process.env.JWT_SEED,
      });

      // Busca al usuario en la base de datos utilizando el ID extraído del payload del token
      const user = await this.authService.findUserById(payload.id);

      // Si el usuario no existe, lanza una excepción de autorización
      if (!user) throw new UnauthorizedException('User doesn´t exist');

      // Si el usuario no está activo, lanza una excepción de autorización
      if (!user.isActive) throw new UnauthorizedException('User is not active');

      // Si todo está bien, asigna el usuario al objeto de la solicitud para su posterior uso en el controlador
      request['user'] = user;
    } catch (error) {
      // Maneja cualquier error durante la verificación del token o la búsqueda del usuario
      switch (error.message) {
        case 'User doesn´t exist':
          throw new UnauthorizedException('User doesn´t exist');
        case 'User is not active':
          throw new UnauthorizedException('User is not active');
        default:
          throw new UnauthorizedException('No estás autorizado');
      }
    }

    // Si no se lanzaron excepciones, permite que la solicitud proceda retornando true
    return true;
  }

  // Método privado para extraer el token del encabezado de autorización
  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers['authorization']?.split(' ') ?? [];
    // Verifica si el tipo de token es 'Bearer'; si es así, retorna el token, si no, retorna undefined
    return type === 'Bearer' ? token : undefined;
  }
}
