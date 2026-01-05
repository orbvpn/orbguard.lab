package database

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"orbguard-lab/internal/config"
	"orbguard-lab/pkg/logger"
)

// PostgresDB wraps the pgx connection pool
type PostgresDB struct {
	pool   *pgxpool.Pool
	logger *logger.Logger
}

// NewPostgres creates a new PostgreSQL connection pool
func NewPostgres(ctx context.Context, cfg config.DatabaseConfig, log *logger.Logger) (*PostgresDB, error) {
	log = log.WithComponent("postgres")
	log.Info().Str("host", cfg.Host).Int("port", cfg.Port).Str("dbname", cfg.DBName).Msg("connecting to PostgreSQL")

	// Parse connection config
	poolConfig, err := pgxpool.ParseConfig(cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("failed to parse database config: %w", err)
	}

	// Configure pool
	poolConfig.MaxConns = int32(cfg.MaxOpenConns)
	poolConfig.MinConns = int32(cfg.MaxIdleConns)
	poolConfig.MaxConnLifetime = cfg.ConnMaxLifetime

	// Add connection lifecycle hooks for logging
	poolConfig.BeforeAcquire = func(ctx context.Context, conn *pgx.Conn) bool {
		return true // Always allow connection acquisition
	}

	poolConfig.AfterRelease = func(conn *pgx.Conn) bool {
		return true // Always return connection to pool
	}

	// Create pool with timeout
	connectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(connectCtx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Verify connection
	if err := pool.Ping(connectCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	log.Info().Msg("connected to PostgreSQL successfully")

	return &PostgresDB{
		pool:   pool,
		logger: log,
	}, nil
}

// Pool returns the underlying connection pool
func (db *PostgresDB) Pool() *pgxpool.Pool {
	return db.pool
}

// Close closes the connection pool
func (db *PostgresDB) Close() {
	db.logger.Info().Msg("closing PostgreSQL connection pool")
	db.pool.Close()
}

// Ping checks the database connection
func (db *PostgresDB) Ping(ctx context.Context) error {
	return db.pool.Ping(ctx)
}

// Stats returns connection pool statistics
func (db *PostgresDB) Stats() *pgxpool.Stat {
	return db.pool.Stat()
}

// Exec executes a query without returning rows
func (db *PostgresDB) Exec(ctx context.Context, sql string, args ...any) error {
	_, err := db.pool.Exec(ctx, sql, args...)
	return err
}

// QueryRow executes a query that returns a single row
func (db *PostgresDB) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return db.pool.QueryRow(ctx, sql, args...)
}

// Query executes a query that returns multiple rows
func (db *PostgresDB) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return db.pool.Query(ctx, sql, args...)
}

// Begin starts a new transaction
func (db *PostgresDB) Begin(ctx context.Context) (pgx.Tx, error) {
	return db.pool.Begin(ctx)
}

// BeginTx starts a new transaction with options
func (db *PostgresDB) BeginTx(ctx context.Context, txOptions pgx.TxOptions) (pgx.Tx, error) {
	return db.pool.BeginTx(ctx, txOptions)
}

// WithTx executes a function within a transaction
func (db *PostgresDB) WithTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback(ctx)
			panic(p)
		}
	}()

	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(ctx); rbErr != nil {
			db.logger.Error().Err(rbErr).Msg("failed to rollback transaction")
		}
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// DBTX is an interface that abstracts database operations for use in queries
// This allows queries to work with both *pgxpool.Pool and pgx.Tx
type DBTX interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// Ensure PostgresDB implements DBTX-like operations through its pool
var _ DBTX = (*pgxpool.Pool)(nil)
