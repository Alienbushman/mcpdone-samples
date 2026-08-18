import type { NextFunction, Request, Response } from "express";

const OK = new Set(["127.0.0.1:3000", "localhost:3000"]);

export function hostGuard(req: Request, res: Response, next: NextFunction) {
  if (!OK.has(req.headers.host ?? "")) {
    res.status(403).send("bad host");
    return;
  }
  next();
}
